import asyncio
import json
import logging
from typing import Dict, Set, Optional, Any
from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger("auth_gateway.realtime")

class RealtimeHub:
    """
    Manages authenticated WebSocket connections and Server-Sent Event (SSE) queues
    with strict isolation per seller identity and administrator role.
    """
    def __init__(self):
        self._seller_ws: Dict[int, Set[WebSocket]] = {}
        self._seller_sse: Dict[int, Set[asyncio.Queue]] = {}
        self._admin_ws: Set[WebSocket] = set()
        self._admin_sse: Set[asyncio.Queue] = set()
        self._lock = asyncio.Lock()

    # --- WebSocket Management ---
    async def connect_seller_ws(self, seller_id: int, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            if seller_id not in self._seller_ws:
                self._seller_ws[seller_id] = set()
            self._seller_ws[seller_id].add(websocket)
        logger.info(f"[REALTIME] Seller #{seller_id} WebSocket connected. Active sockets: {len(self._seller_ws[seller_id])}")

    async def disconnect_seller_ws(self, seller_id: int, websocket: WebSocket):
        async with self._lock:
            if seller_id in self._seller_ws:
                self._seller_ws[seller_id].discard(websocket)
                if not self._seller_ws[seller_id]:
                    del self._seller_ws[seller_id]
        logger.info(f"[REALTIME] Seller #{seller_id} WebSocket disconnected.")

    async def connect_admin_ws(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self._admin_ws.add(websocket)
        logger.info(f"[REALTIME] Admin WebSocket connected. Active sockets: {len(self._admin_ws)}")

    async def disconnect_admin_ws(self, websocket: WebSocket):
        async with self._lock:
            self._admin_ws.discard(websocket)
        logger.info("[REALTIME] Admin WebSocket disconnected.")

    # --- SSE Management ---
    async def register_seller_sse(self, seller_id: int) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        async with self._lock:
            if seller_id not in self._seller_sse:
                self._seller_sse[seller_id] = set()
            self._seller_sse[seller_id].add(q)
        return q

    async def unregister_seller_sse(self, seller_id: int, q: asyncio.Queue):
        async with self._lock:
            if seller_id in self._seller_sse:
                self._seller_sse[seller_id].discard(q)
                if not self._seller_sse[seller_id]:
                    del self._seller_sse[seller_id]

    async def register_admin_sse(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        async with self._lock:
            self._admin_sse.add(q)
        return q

    async def unregister_admin_sse(self, q: asyncio.Queue):
        async with self._lock:
            self._admin_sse.discard(q)

    # --- Event Dispatch ---
    async def dispatch_seller_event(self, seller_id: int, event_type: str, payload: Dict[str, Any]):
        """
        Dispatches an event strictly to the designated seller's active sessions.
        Never leaks to other sellers or unauthorized clients.
        """
        message = {
            "type": event_type,
            "seller_id": seller_id,
            "data": payload,
            "timestamp": asyncio.get_event_loop().time()
        }
        msg_str = json.dumps(message)

        # 1. WebSockets
        dead_ws = set()
        async with self._lock:
            sockets = list(self._seller_ws.get(seller_id, []))
            sse_queues = list(self._seller_sse.get(seller_id, []))

        for ws in sockets:
            try:
                await ws.send_text(msg_str)
            except Exception:
                dead_ws.add(ws)

        if dead_ws:
            async with self._lock:
                if seller_id in self._seller_ws:
                    self._seller_ws[seller_id].difference_update(dead_ws)

        # 2. SSE Queues
        for q in sse_queues:
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                pass

    async def dispatch_admin_event(self, event_type: str, payload: Dict[str, Any]):
        """
        Dispatches an event to authenticated administrator sessions.
        """
        message = {
            "type": event_type,
            "role": "admin",
            "data": payload,
            "timestamp": asyncio.get_event_loop().time()
        }
        msg_str = json.dumps(message)

        dead_ws = set()
        async with self._lock:
            admin_sockets = list(self._admin_ws)
            admin_queues = list(self._admin_sse)

        for ws in admin_sockets:
            try:
                await ws.send_text(msg_str)
            except Exception:
                dead_ws.add(ws)

        if dead_ws:
            async with self._lock:
                self._admin_ws.difference_update(dead_ws)

        for q in admin_queues:
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                pass

    async def dispatch_global_event(self, event_type: str, payload: Dict[str, Any]):
        """
        Dispatches a broadcast event to all connected sellers and administrators
        (e.g. version updates, system policy changes).
        """
        async with self._lock:
            seller_ids = list(self._seller_ws.keys())
        for sid in seller_ids:
            await self.dispatch_seller_event(sid, event_type, payload)
        await self.dispatch_admin_event(event_type, payload)

# Singleton real-time hub
realtime_hub = RealtimeHub()
