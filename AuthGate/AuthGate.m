//
//  AuthGate.m
//  3105 Subscription & Access Control Gatekeeper
//  All-In-One Single-File Implementation with BSD Raw Socket Engine & Scene-Aware Enforcement
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <sys/utsname.h>
#import <objc/runtime.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <netdb.h>
#import <unistd.h>
#import <fcntl.h>

#define AUTHGATE_VERSION @"1.1.3"
#define DEFAULT_SERVER_HOST @"fi9.bot-hosting.cloud"
#define DEFAULT_SERVER_IP @"95.216.12.48"
#define DEFAULT_SERVER_PORT 25808
#define DISCORD_URL @"https://discord.gg/KPJzd42rme"
#define KEYCHAIN_SERVICE @"com.authgate.session.service"
#define KEYCHAIN_ACCOUNT_KEY @"com.authgate.license.key"
#define KEYCHAIN_ACCOUNT_TOKEN @"com.authgate.session.token"
#define KEYCHAIN_ACCOUNT_HWID @"com.authgate.device.hwid"

#pragma mark - Keychain, Device Fingerprint & BSD Socket Engine

@interface AuthGateSecurity : NSObject
+ (NSString *)getDeviceHWID;
+ (BOOL)saveLicenseKey:(NSString *)key sessionToken:(NSString *)token;
+ (nullable NSString *)getSavedLicenseKey;
+ (nullable NSString *)getSavedSessionToken;
+ (void)clearSession;
+ (void)rawSocketPostWithPath:(NSString *)path
                     jsonBody:(NSString *)bodyJson
                      timeout:(int)timeoutSec
                   completion:(void (^)(NSInteger statusCode, NSDictionary * _Nullable jsonResp, NSError * _Nullable error))completion;
@end

@implementation AuthGateSecurity

+ (NSString *)sha256:(NSString *)input {
    const char *cstr = [input UTF8String];
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(cstr, (CC_LONG)strlen(cstr), result);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hex appendFormat:@"%02x", result[i]];
    }
    return [hex copy];
}

+ (NSString *)getDeviceHWID {
    NSString *cached = [self loadFromKeychain:KEYCHAIN_ACCOUNT_HWID];
    if (cached && cached.length == 64) return cached;

    NSString *idfv = [[[UIDevice currentDevice] identifierForVendor] UUIDString] ?: [[NSUUID UUID] UUIDString];
    struct utsname sysInfo;
    uname(&sysInfo);
    NSString *model = [NSString stringWithCString:sysInfo.machine encoding:NSUTF8StringEncoding] ?: @"iPhone";
    NSString *osVer = [[UIDevice currentDevice] systemVersion] ?: @"iOS";

    NSString *raw = [NSString stringWithFormat:@"%@::%@::%@::::3105_SALT_PROD", idfv, model, osVer];
    NSString *hwid = [self sha256:raw];
    [self saveToKeychain:KEYCHAIN_ACCOUNT_HWID value:hwid];
    return hwid;
}

+ (BOOL)saveToKeychain:(NSString *)account value:(NSString *)value {
    if (!value) return NO;
    NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: KEYCHAIN_SERVICE,
        (__bridge id)kSecAttrAccount: account
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
    NSDictionary *attrs = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: KEYCHAIN_SERVICE,
        (__bridge id)kSecAttrAccount: account,
        (__bridge id)kSecValueData: data,
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    };
    return (SecItemAdd((__bridge CFDictionaryRef)attrs, NULL) == errSecSuccess);
}

+ (nullable NSString *)loadFromKeychain:(NSString *)account {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: KEYCHAIN_SERVICE,
        (__bridge id)kSecAttrAccount: account,
        (__bridge id)kSecReturnData: (__bridge id)kCFBooleanTrue,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne
    };
    CFTypeRef result = NULL;
    if (SecItemCopyMatching((__bridge CFDictionaryRef)query, &result) == errSecSuccess && result != NULL) {
        NSData *data = (__bridge_transfer NSData *)result;
        return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    return nil;
}

+ (BOOL)saveLicenseKey:(NSString *)key sessionToken:(NSString *)token {
    BOOL b1 = [self saveToKeychain:KEYCHAIN_ACCOUNT_KEY value:key];
    BOOL b2 = [self saveToKeychain:KEYCHAIN_ACCOUNT_TOKEN value:token];
    return b1 && b2;
}

+ (nullable NSString *)getSavedLicenseKey {
    return [self loadFromKeychain:KEYCHAIN_ACCOUNT_KEY];
}

+ (nullable NSString *)getSavedSessionToken {
    return [self loadFromKeychain:KEYCHAIN_ACCOUNT_TOKEN];
}

+ (void)clearSession {
    NSDictionary *q1 = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword, (__bridge id)kSecAttrService: KEYCHAIN_SERVICE, (__bridge id)kSecAttrAccount: KEYCHAIN_ACCOUNT_KEY};
    NSDictionary *q2 = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword, (__bridge id)kSecAttrService: KEYCHAIN_SERVICE, (__bridge id)kSecAttrAccount: KEYCHAIN_ACCOUNT_TOKEN};
    SecItemDelete((__bridge CFDictionaryRef)q1);
    SecItemDelete((__bridge CFDictionaryRef)q2);
}

#pragma mark - Direct BSD Socket HTTP Engine (Bypasses iOS Sandbox & ATS blocks)

+ (void)rawSocketPostWithPath:(NSString *)path
                     jsonBody:(NSString *)bodyJson
                      timeout:(int)timeoutSec
                   completion:(void (^)(NSInteger statusCode, NSDictionary * _Nullable jsonResp, NSError * _Nullable error))completion {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        NSArray<NSString *> *targetHosts = @[DEFAULT_SERVER_IP, DEFAULT_SERVER_HOST];
        int port = DEFAULT_SERVER_PORT;
        NSError *lastErr = nil;
        
        for (NSString *host in targetHosts) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) {
                lastErr = [NSError errorWithDomain:@"BSDNetwork" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"socket() failed"}];
                continue;
            }
            
            struct timeval tv;
            tv.tv_sec = timeoutSec;
            tv.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
            
            struct sockaddr_in serv_addr;
            memset(&serv_addr, 0, sizeof(serv_addr));
            serv_addr.sin_family = AF_INET;
            serv_addr.sin_port = htons(port);
            
            int ptonRes = inet_pton(AF_INET, [host UTF8String], &serv_addr.sin_addr);
            if (ptonRes <= 0) {
                struct hostent *he = gethostbyname([host UTF8String]);
                if (!he || !he->h_addr_list[0]) {
                    close(sock);
                    lastErr = [NSError errorWithDomain:@"BSDNetwork" code:-2 userInfo:@{NSLocalizedDescriptionKey: @"DNS host resolution failed"}];
                    continue;
                }
                memcpy(&serv_addr.sin_addr, he->h_addr_list[0], sizeof(struct in_addr));
            }
            
            if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
                close(sock);
                lastErr = [NSError errorWithDomain:@"BSDNetwork" code:-3 userInfo:@{NSLocalizedDescriptionKey: @"TCP connect timeout/refused"}];
                continue;
            }
            
            NSString *httpReq = [NSString stringWithFormat:
                @"POST %@ HTTP/1.1\r\n"
                @"Host: %@:%d\r\n"
                @"User-Agent: 3105-iOS/1.1.3\r\n"
                @"Content-Type: application/json\r\n"
                @"Accept: application/json\r\n"
                @"Content-Length: %lu\r\n"
                @"Connection: close\r\n\r\n%@",
                path, DEFAULT_SERVER_HOST, port, (unsigned long)[bodyJson lengthOfBytesUsingEncoding:NSUTF8StringEncoding], bodyJson];
            
            const char *rawBuf = [httpReq UTF8String];
            size_t total = strlen(rawBuf);
            size_t sent = 0;
            while (sent < total) {
                ssize_t s = send(sock, rawBuf + sent, total - sent, 0);
                if (s <= 0) break;
                sent += s;
            }
            
            NSMutableData *recvData = [NSMutableData data];
            char inBuf[2048];
            ssize_t r = 0;
            while ((r = recv(sock, inBuf, sizeof(inBuf) - 1, 0)) > 0) {
                [recvData appendBytes:inBuf length:r];
            }
            close(sock);
            
            NSString *respStr = [[NSString alloc] initWithData:recvData encoding:NSUTF8StringEncoding];
            if (!respStr || respStr.length == 0) {
                lastErr = [NSError errorWithDomain:@"BSDNetwork" code:-4 userInfo:@{NSLocalizedDescriptionKey: @"Empty response received"}];
                continue;
            }
            
            NSInteger statusCode = 0;
            NSDictionary *jsonDict = nil;
            NSRange delim = [respStr rangeOfString:@"\r\n\r\n"];
            if (delim.location != NSNotFound) {
                NSString *headers = [respStr substringToIndex:delim.location];
                NSString *body = [respStr substringFromIndex:delim.location + 4];
                NSArray *lines = [headers componentsSeparatedByString:@"\r\n"];
                if (lines.count > 0) {
                    NSArray *tokens = [lines[0] componentsSeparatedByString:@" "];
                    if (tokens.count >= 2) {
                        statusCode = [tokens[1] integerValue];
                    }
                }
                if (body.length > 0) {
                    NSData *bData = [body dataUsingEncoding:NSUTF8StringEncoding];
                    if (bData) {
                        jsonDict = [NSJSONSerialization JSONObjectWithData:bData options:0 error:nil];
                    }
                }
            }
            
            dispatch_async(dispatch_get_main_queue(), ^{
                completion(statusCode, jsonDict, nil);
            });
            return;
        }
        
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(0, nil, lastErr ?: [NSError errorWithDomain:@"BSDNetwork" code:-1009 userInfo:@{NSLocalizedDescriptionKey: @"Network error: unable to reach license server"}]);
        });
    });
}

+ (void)installBundledDefaultPatches {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
    
    NSString *docDir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *appSupportDir = [NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES) firstObject];
    
    // 3105 internal installed patch store directory (PatchProjectLibrary.packageRootURL)
    NSString *installedPatchesDir = [appSupportDir stringByAppendingPathComponent:@"PatchProjects"];
    NSString *installedAuthorCopiesDir = [installedPatchesDir stringByAppendingPathComponent:@".AuthorCopies"];
    NSString *installedBackupsDir = [installedPatchesDir stringByAppendingPathComponent:@"Backups"];
    NSString *altAppSupportDir = [appSupportDir stringByAppendingPathComponent:@"3105/PatchProjects"];
    
    NSString *docPatchesDir = [docDir stringByAppendingPathComponent:@"Patches"];
    NSString *docPackagesDir = [docDir stringByAppendingPathComponent:@"Packages"];
    NSString *docProjectsDir = [docDir stringByAppendingPathComponent:@"Projects"];
    
    NSArray *dirsToCreate = @[
        installedPatchesDir,
        installedAuthorCopiesDir,
        installedBackupsDir,
        altAppSupportDir,
        docPatchesDir,
        docPackagesDir,
        docProjectsDir
    ];
    
    for (NSString *d in dirsToCreate) {
        [fm createDirectoryAtPath:d withIntermediateDirectories:YES attributes:nil error:nil];
    }
    
    NSMutableArray *searchPaths = [NSMutableArray arrayWithObject:bundlePath];
    NSString *bundlePatches = [bundlePath stringByAppendingPathComponent:@"Patches"];
    if ([fm fileExistsAtPath:bundlePatches]) {
        [searchPaths addObject:bundlePatches];
    }
    
    for (NSString *dir in searchPaths) {
        NSArray *files = [fm contentsOfDirectoryAtPath:dir error:nil];
        for (NSString *file in files) {
            if ([file.pathExtension.lowercaseString isEqualToString:@"3105"]) {
                NSString *src = [dir stringByAppendingPathComponent:file];
                
                // Target 1: Library/Application Support/PatchProjects (Primary Installed Patches Store)
                NSString *dstInstalled = [installedPatchesDir stringByAppendingPathComponent:file];
                if (![fm fileExistsAtPath:dstInstalled]) {
                    [fm copyItemAtPath:src toPath:dstInstalled error:nil];
                    NSLog(@"[AuthGate] Installed patch to store: %@", dstInstalled);
                }
                
                // Target 2: Library/Application Support/PatchProjects/.AuthorCopies
                NSString *dstAuthor = [installedAuthorCopiesDir stringByAppendingPathComponent:file];
                if (![fm fileExistsAtPath:dstAuthor]) {
                    [fm copyItemAtPath:src toPath:dstAuthor error:nil];
                }
                
                // Target 3: Library/Application Support/3105/PatchProjects
                NSString *dstAlt = [altAppSupportDir stringByAppendingPathComponent:file];
                if (![fm fileExistsAtPath:dstAlt]) {
                    [fm copyItemAtPath:src toPath:dstAlt error:nil];
                }
                
                // Target 4: Documents/Patches
                NSString *dstPatches = [docPatchesDir stringByAppendingPathComponent:file];
                if (![fm fileExistsAtPath:dstPatches]) {
                    [fm copyItemAtPath:src toPath:dstPatches error:nil];
                }
                
                // Target 5: Documents/Projects
                NSString *dstProjects = [docProjectsDir stringByAppendingPathComponent:file];
                if (![fm fileExistsAtPath:dstProjects]) {
                    [fm copyItemAtPath:src toPath:dstProjects error:nil];
                }
                
                // Target 6: Documents/Packages
                NSString *dstPackages = [docPackagesDir stringByAppendingPathComponent:file];
                if (![fm fileExistsAtPath:dstPackages]) {
                    [fm copyItemAtPath:src toPath:dstPackages error:nil];
                }
                
                // Target 7: Documents root
                NSString *dstDoc = [docDir stringByAppendingPathComponent:file];
                if (![fm fileExistsAtPath:dstDoc]) {
                    [fm copyItemAtPath:src toPath:dstDoc error:nil];
                }
            }
        }
    }
}

@end

#pragma mark - AuthGate View Controller (Full Native UI)

@interface AuthGateViewController : UIViewController <UITextFieldDelegate>
@property (nonatomic, copy) void (^onSuccess)(void);
- (void)startSilentValidationIfPossible;
@end

@implementation AuthGateViewController {
    UIView *_cardView;
    UILabel *_titleLabel;
    UILabel *_versionBadge;
    UILabel *_subtitleLabel;
    UITextField *_keyField;
    UIButton *_activateButton;
    UIActivityIndicatorView *_spinner;
    UILabel *_statusLabel;
    UIButton *_discordButton;
    BOOL _isAuthenticating;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    [self setupUI];
    
    NSString *savedKey = [AuthGateSecurity getSavedLicenseKey];
    if (savedKey && savedKey.length > 0) {
        _keyField.text = savedKey;
    }
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    [self startSilentValidationIfPossible];
}

- (UIStatusBarStyle)preferredStatusBarStyle {
    return UIStatusBarStyleLightContent;
}

- (void)setupUI {
    self.view.backgroundColor = [UIColor colorWithRed:0.04 green:0.04 blue:0.06 alpha:1.0]; // Deep Dark Obsidian
    
    // Tap to dismiss keyboard
    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:self.view action:@selector(endEditing:)];
    [self.view addGestureRecognizer:tap];
    
    // Card Container
    _cardView = [[UIView alloc] init];
    _cardView.translatesAutoresizingMaskIntoConstraints = NO;
    _cardView.backgroundColor = [UIColor colorWithRed:0.08 green:0.08 blue:0.11 alpha:0.98];
    _cardView.layer.cornerRadius = 24.0;
    _cardView.layer.borderWidth = 1.0;
    _cardView.layer.borderColor = [UIColor colorWithRed:0.35 green:0.22 blue:0.16 alpha:0.55].CGColor;
    _cardView.layer.shadowColor = [UIColor blackColor].CGColor;
    _cardView.layer.shadowOpacity = 0.7;
    _cardView.layer.shadowOffset = CGSizeMake(0, 12);
    _cardView.layer.shadowRadius = 24.0;
    [self.view addSubview:_cardView];
    
    // Title
    _titleLabel = [[UILabel alloc] init];
    _titleLabel.translatesAutoresizingMaskIntoConstraints = NO;
    _titleLabel.text = @"BYTE IOS";
    _titleLabel.textColor = [UIColor whiteColor];
    _titleLabel.font = [UIFont systemFontOfSize:30 weight:UIFontWeightHeavy];
    [_cardView addSubview:_titleLabel];
    
    // Version Badge - Warm Peach / Neon Amber Accent
    _versionBadge = [[UILabel alloc] init];
    _versionBadge.translatesAutoresizingMaskIntoConstraints = NO;
    _versionBadge.text = @" 27 ";
    _versionBadge.textColor = [UIColor colorWithRed:1.0 green:0.62 blue:0.40 alpha:1.0];
    _versionBadge.backgroundColor = [UIColor colorWithRed:0.38 green:0.18 blue:0.08 alpha:0.55];
    _versionBadge.layer.borderColor = [UIColor colorWithRed:1.0 green:0.62 blue:0.40 alpha:0.45].CGColor;
    _versionBadge.layer.borderWidth = 1.0;
    _versionBadge.font = [UIFont systemFontOfSize:13 weight:UIFontWeightHeavy];
    _versionBadge.layer.cornerRadius = 6.0;
    _versionBadge.layer.masksToBounds = YES;
    [_cardView addSubview:_versionBadge];
    
    // Subtitle
    _subtitleLabel = [[UILabel alloc] init];
    _subtitleLabel.translatesAutoresizingMaskIntoConstraints = NO;
    _subtitleLabel.text = @"Subscription License Authentication";
    _subtitleLabel.textColor = [UIColor colorWithRed:0.62 green:0.66 blue:0.75 alpha:1.0];
    _subtitleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    [_cardView addSubview:_subtitleLabel];
    
    // Input Container
    UIView *inputBox = [[UIView alloc] init];
    inputBox.translatesAutoresizingMaskIntoConstraints = NO;
    inputBox.backgroundColor = [UIColor colorWithRed:0.05 green:0.05 blue:0.08 alpha:0.95];
    inputBox.layer.cornerRadius = 14.0;
    inputBox.layer.borderWidth = 1.0;
    inputBox.layer.borderColor = [UIColor colorWithRed:0.32 green:0.22 blue:0.18 alpha:0.65].CGColor;
    [_cardView addSubview:inputBox];
    
    _keyField = [[UITextField alloc] init];
    _keyField.translatesAutoresizingMaskIntoConstraints = NO;
    _keyField.placeholder = @"BYTE-XXXX-XXXX-XXXX";
    _keyField.textColor = [UIColor whiteColor];
    _keyField.font = [UIFont fontWithName:@"Menlo" size:15] ?: [UIFont monospacedSystemFontOfSize:15 weight:UIFontWeightSemibold];
    _keyField.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
    _keyField.autocorrectionType = UITextAutocorrectionTypeNo;
    _keyField.spellCheckingType = UITextSpellCheckingTypeNo;
    _keyField.returnKeyType = UIReturnKeyDone;
    _keyField.delegate = self;
    _keyField.attributedPlaceholder = [[NSAttributedString alloc] initWithString:@"BYTE-XXXX-XXXX-XXXX"
                                                                      attributes:@{NSForegroundColorAttributeName: [UIColor colorWithWhite:0.35 alpha:1.0]}];
    [inputBox addSubview:_keyField];
    
    // Paste Button inside input box
    UIButton *pasteBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    pasteBtn.translatesAutoresizingMaskIntoConstraints = NO;
    [pasteBtn setTitle:@"Paste" forState:UIControlStateNormal];
    pasteBtn.titleLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightBold];
    [pasteBtn setTitleColor:[UIColor colorWithRed:1.0 green:0.62 blue:0.40 alpha:1.0] forState:UIControlStateNormal];
    [pasteBtn addTarget:self action:@selector(pasteKeyFromClipboard) forControlEvents:UIControlEventTouchUpInside];
    [inputBox addSubview:pasteBtn];
    
    // Activate Button - Warm Glowing Peach Accent
    _activateButton = [UIButton buttonWithType:UIButtonTypeCustom];
    _activateButton.translatesAutoresizingMaskIntoConstraints = NO;
    _activateButton.backgroundColor = [UIColor colorWithRed:0.98 green:0.50 blue:0.24 alpha:1.0];
    _activateButton.layer.cornerRadius = 14.0;
    _activateButton.layer.shadowColor = [UIColor colorWithRed:0.98 green:0.50 blue:0.24 alpha:0.45].CGColor;
    _activateButton.layer.shadowOpacity = 0.85;
    _activateButton.layer.shadowOffset = CGSizeMake(0, 6);
    _activateButton.layer.shadowRadius = 14.0;
    [_activateButton setTitle:@"ACTIVATE SUBSCRIPTION" forState:UIControlStateNormal];
    [_activateButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    _activateButton.titleLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightBold];
    [_activateButton addTarget:self action:@selector(activateButtonTapped) forControlEvents:UIControlEventTouchUpInside];
    [_cardView addSubview:_activateButton];
    
    _spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    _spinner.translatesAutoresizingMaskIntoConstraints = NO;
    _spinner.color = [UIColor whiteColor];
    _spinner.hidesWhenStopped = YES;
    [_activateButton addSubview:_spinner];
    
    // Status Label
    _statusLabel = [[UILabel alloc] init];
    _statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    _statusLabel.textColor = [UIColor colorWithRed:1.0 green:0.42 blue:0.42 alpha:1.0];
    _statusLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    _statusLabel.numberOfLines = 0;
    _statusLabel.textAlignment = NSTextAlignmentCenter;
    [_cardView addSubview:_statusLabel];
    
    // Discord Button
    _discordButton = [UIButton buttonWithType:UIButtonTypeCustom];
    _discordButton.translatesAutoresizingMaskIntoConstraints = NO;
    [_discordButton setTitle:@"💬 Join Discord Community / Buy Key" forState:UIControlStateNormal];
    [_discordButton setTitleColor:[UIColor colorWithRed:1.0 green:0.68 blue:0.48 alpha:1.0] forState:UIControlStateNormal];
    _discordButton.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightSemibold];
    [_discordButton addTarget:self action:@selector(discordButtonTapped) forControlEvents:UIControlEventTouchUpInside];
    [_cardView addSubview:_discordButton];
    
    // Auto-Layout Constraints
    [NSLayoutConstraint activateConstraints:@[
        [_cardView.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor constant:-20],
        [_cardView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:24],
        [_cardView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-24],
        
        [_titleLabel.topAnchor constraintEqualToAnchor:_cardView.topAnchor constant:28],
        [_titleLabel.centerXAnchor constraintEqualToAnchor:_cardView.centerXAnchor constant:-25],
        
        [_versionBadge.centerYAnchor constraintEqualToAnchor:_titleLabel.centerYAnchor],
        [_versionBadge.leadingAnchor constraintEqualToAnchor:_titleLabel.trailingAnchor constant:8],
        [_versionBadge.heightAnchor constraintEqualToConstant:22],
        
        [_subtitleLabel.topAnchor constraintEqualToAnchor:_titleLabel.bottomAnchor constant:4],
        [_subtitleLabel.centerXAnchor constraintEqualToAnchor:_cardView.centerXAnchor],
        
        [inputBox.topAnchor constraintEqualToAnchor:_subtitleLabel.bottomAnchor constant:24],
        [inputBox.leadingAnchor constraintEqualToAnchor:_cardView.leadingAnchor constant:20],
        [inputBox.trailingAnchor constraintEqualToAnchor:_cardView.trailingAnchor constant:-20],
        [inputBox.heightAnchor constraintEqualToConstant:50],
        
        [_keyField.leadingAnchor constraintEqualToAnchor:inputBox.leadingAnchor constant:14],
        [_keyField.trailingAnchor constraintEqualToAnchor:pasteBtn.leadingAnchor constant:-8],
        [_keyField.centerYAnchor constraintEqualToAnchor:inputBox.centerYAnchor],
        
        [pasteBtn.trailingAnchor constraintEqualToAnchor:inputBox.trailingAnchor constant:-12],
        [pasteBtn.centerYAnchor constraintEqualToAnchor:inputBox.centerYAnchor],
        [pasteBtn.widthAnchor constraintEqualToConstant:48],
        
        [_activateButton.topAnchor constraintEqualToAnchor:inputBox.bottomAnchor constant:18],
        [_activateButton.leadingAnchor constraintEqualToAnchor:_cardView.leadingAnchor constant:20],
        [_activateButton.trailingAnchor constraintEqualToAnchor:_cardView.trailingAnchor constant:-20],
        [_activateButton.heightAnchor constraintEqualToConstant:50],
        
        [_spinner.centerYAnchor constraintEqualToAnchor:_activateButton.centerYAnchor],
        [_spinner.trailingAnchor constraintEqualToAnchor:_activateButton.trailingAnchor constant:-16],
        
        [_statusLabel.topAnchor constraintEqualToAnchor:_activateButton.bottomAnchor constant:12],
        [_statusLabel.leadingAnchor constraintEqualToAnchor:_cardView.leadingAnchor constant:20],
        [_statusLabel.trailingAnchor constraintEqualToAnchor:_cardView.trailingAnchor constant:-20],
        
        [_discordButton.topAnchor constraintEqualToAnchor:_statusLabel.bottomAnchor constant:14],
        [_discordButton.centerXAnchor constraintEqualToAnchor:_cardView.centerXAnchor],
        [_discordButton.bottomAnchor constraintEqualToAnchor:_cardView.bottomAnchor constant:-20]
    ]];
}

- (void)pasteKeyFromClipboard {
    NSString *pasteString = [UIPasteboard generalPasteboard].string;
    if (pasteString && pasteString.length > 0) {
        _keyField.text = [pasteString stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    }
}

- (void)discordButtonTapped {
    NSURL *url = [NSURL URLWithString:DISCORD_URL];
    if (@available(iOS 10.0, *)) {
        [[UIApplication sharedApplication] openURL:url options:@{} completionHandler:nil];
    } else {
        [[UIApplication sharedApplication] openURL:url];
    }
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    [textField resignFirstResponder];
    [self activateButtonTapped];
    return YES;
}

- (void)startSilentValidationIfPossible {
    NSString *savedToken = [AuthGateSecurity getSavedSessionToken];
    NSString *savedKey = [AuthGateSecurity getSavedLicenseKey];
    if (!savedToken || !savedKey || _isAuthenticating) return;
    
    _isAuthenticating = YES;
    [_spinner startAnimating];
    _activateButton.enabled = NO;
    _statusLabel.textColor = [UIColor colorWithRed:0.60 green:0.75 blue:0.95 alpha:1.0];
    _statusLabel.text = @"Checking saved license...";
    
    NSDictionary *body = @{
        @"token": savedToken,
        @"device_hash": [AuthGateSecurity getDeviceHWID],
        @"app_version": AUTHGATE_VERSION
    };
    NSData *bodyData = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
    NSString *bodyJson = [[NSString alloc] initWithData:bodyData encoding:NSUTF8StringEncoding];
    
    [AuthGateSecurity rawSocketPostWithPath:@"/api/v1/auth/validate" jsonBody:bodyJson timeout:8 completion:^(NSInteger statusCode, NSDictionary * _Nullable json, NSError * _Nullable error) {
        self->_isAuthenticating = NO;
        [self->_spinner stopAnimating];
        self->_activateButton.enabled = YES;
        
        if (statusCode == 200) {
            self->_statusLabel.textColor = [UIColor colorWithRed:0.35 green:0.85 blue:0.60 alpha:1.0];
            self->_statusLabel.text = @"✓ Subscription Active!";
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                if (self.onSuccess) self.onSuccess();
            });
        } else {
            [AuthGateSecurity clearSession];
            self->_statusLabel.textColor = [UIColor colorWithRed:0.95 green:0.40 blue:0.40 alpha:1.0];
            self->_statusLabel.text = @"Session expired. Please enter license key.";
        }
    }];
}

- (void)activateButtonTapped {
    if (_isAuthenticating) return;
    
    NSString *key = [_keyField.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (!key || key.length == 0) {
        _statusLabel.textColor = [UIColor colorWithRed:0.95 green:0.40 blue:0.40 alpha:1.0];
        _statusLabel.text = @"Please enter your license key.";
        return;
    }
    
    _isAuthenticating = YES;
    [_spinner startAnimating];
    _activateButton.enabled = NO;
    _activateButton.alpha = 0.7;
    _statusLabel.textColor = [UIColor colorWithRed:1.0 green:0.75 blue:0.55 alpha:1.0];
    _statusLabel.text = @"Verifying with license server...";
    
    NSString *hwid = [AuthGateSecurity getDeviceHWID];
    NSDictionary *body = @{
        @"key": key,
        @"license_key": key,
        @"device_hash": hwid,
        @"app_version": AUTHGATE_VERSION
    };
    
    NSData *bodyData = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
    NSString *bodyJson = [[NSString alloc] initWithData:bodyData encoding:NSUTF8StringEncoding];
    
    [AuthGateSecurity rawSocketPostWithPath:@"/api/v1/auth/login" jsonBody:bodyJson timeout:12 completion:^(NSInteger statusCode, NSDictionary * _Nullable json, NSError * _Nullable error) {
        self->_isAuthenticating = NO;
        [self->_spinner stopAnimating];
        self->_activateButton.enabled = YES;
        self->_activateButton.alpha = 1.0;
        
        if (error || statusCode == 0) {
            self->_statusLabel.textColor = [UIColor colorWithRed:1.0 green:0.42 blue:0.42 alpha:1.0];
            self->_statusLabel.text = [NSString stringWithFormat:@"❌ (%ld) %@", (long)(error ? error.code : -1), error ? error.localizedDescription : @"Connection failed"];
            return;
        }
        
        BOOL success = (statusCode == 200 && json && ([json[@"success"] boolValue] || json[@"token"]));
        if (success) {
            NSString *token = json[@"token"] ?: @"SESSION_ACTIVE";
            [AuthGateSecurity saveLicenseKey:key sessionToken:token];
            
            self->_statusLabel.textColor = [UIColor colorWithRed:0.35 green:0.88 blue:0.60 alpha:1.0];
            self->_statusLabel.text = @"✓ Access Granted! Unlocking BYTE IOS...";
            
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                if (self.onSuccess) self.onSuccess();
            });
        } else {
            NSString *errMsg = json[@"detail"] ?: (json[@"message"] ?: @"Invalid or expired license key.");
            self->_statusLabel.textColor = [UIColor colorWithRed:1.0 green:0.42 blue:0.42 alpha:1.0];
            self->_statusLabel.text = [NSString stringWithFormat:@"❌ %@", errMsg];
        }
    }];
}

@end

#pragma mark - Master Gatekeeper Controller & Window Presenter

@interface AuthGateManager : NSObject
+ (instancetype)shared;
- (void)enforceGate;
- (void)dismissGate;
@property (nonatomic, assign) BOOL isUnlocked;
@property (nonatomic, strong, nullable) UIWindow *gateWindow;
@end

@implementation AuthGateManager {
    AuthGateViewController *_authVC;
}

+ (instancetype)shared {
    static AuthGateManager *inst = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ inst = [[AuthGateManager alloc] init]; });
    return inst;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _isUnlocked = NO;
    }
    return self;
}

- (void)enforceGate {
    if (self.isUnlocked) return;
    
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self.isUnlocked) return;
        
        UIWindowScene *activeScene = nil;
        if (@available(iOS 13.0, *)) {
            for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
                if ([scene isKindOfClass:[UIWindowScene class]]) {
                    UIWindowScene *ws = (UIWindowScene *)scene;
                    if (ws.activationState == UISceneActivationStateForegroundActive) {
                        activeScene = ws;
                        break;
                    }
                    if (!activeScene) activeScene = ws;
                }
            }
        }
        
        if (!self->_authVC) {
            self->_authVC = [[AuthGateViewController alloc] init];
            __weak typeof(self) weakSelf = self;
            self->_authVC.onSuccess = ^{
                [weakSelf dismissGate];
            };
        }
        
        // Recreate or attach gateWindow to active scene
        if (@available(iOS 13.0, *)) {
            if (activeScene) {
                if (!self.gateWindow || self.gateWindow.windowScene != activeScene) {
                    self.gateWindow = [[UIWindow alloc] initWithWindowScene:activeScene];
                }
            } else if (!self.gateWindow) {
                self.gateWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
            }
        } else {
            if (!self.gateWindow) {
                self.gateWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
            }
        }
        
        if (self.gateWindow) {
            self.gateWindow.windowLevel = UIWindowLevelAlert + 99999.0;
            self.gateWindow.rootViewController = self->_authVC;
            self.gateWindow.backgroundColor = [UIColor colorWithRed:0.05 green:0.06 blue:0.09 alpha:1.0];
            self.gateWindow.hidden = NO;
            [self.gateWindow makeKeyAndVisible];
        }
    });
}

- (void)dismissGate {
    self.isUnlocked = YES;
    [AuthGateSecurity installBundledDefaultPatches];
    if (!self.gateWindow) return;
    
    [UIView animateWithDuration:0.4 animations:^{
        self.gateWindow.alpha = 0.0;
        self.gateWindow.transform = CGAffineTransformMakeScale(1.08, 1.08);
    } completion:^(BOOL finished) {
        self.gateWindow.hidden = YES;
        self.gateWindow.rootViewController = nil;
        self.gateWindow = nil;
    }];
}

@end

#pragma mark - Method Swizzling for Guaranteed Enforcement

static void (*orig_viewDidAppear)(id, SEL, BOOL);
static void swizzled_viewDidAppear(UIViewController *self, SEL _cmd, BOOL animated) {
    orig_viewDidAppear(self, _cmd, animated);
    if (![AuthGateManager shared].isUnlocked && ![self isKindOfClass:[AuthGateViewController class]]) {
        [[AuthGateManager shared] enforceGate];
    }
}

static void (*orig_makeKeyAndVisible)(id, SEL);
static void swizzled_makeKeyAndVisible(UIWindow *self, SEL _cmd) {
    orig_makeKeyAndVisible(self, _cmd);
    if (![AuthGateManager shared].isUnlocked && self != [AuthGateManager shared].gateWindow) {
        [[AuthGateManager shared] enforceGate];
    }
}

static void SwizzleMethod(Class cls, SEL origSel, IMP newImp, void (**origImpOut)(void)) {
    Method m = class_getInstanceMethod(cls, origSel);
    if (m) {
        IMP orig = method_getImplementation(m);
        if (origImpOut) *origImpOut = (void (*)(void))orig;
        method_setImplementation(m, newImp);
    }
}

#pragma mark - Constructor & Lifecycle Hooks

__attribute__((constructor))
static void AuthGateInit(void) {
    // Install bundled default patches into Documents & Patches folders
    [AuthGateSecurity installBundledDefaultPatches];
    
    // 1. Swizzle UIViewController viewDidAppear
    SwizzleMethod([UIViewController class], @selector(viewDidAppear:), (IMP)swizzled_viewDidAppear, (void (**)(void))&orig_viewDidAppear);
    
    // 2. Swizzle UIWindow makeKeyAndVisible
    SwizzleMethod([UIWindow class], @selector(makeKeyAndVisible), (IMP)swizzled_makeKeyAndVisible, (void (**)(void))&orig_makeKeyAndVisible);
    
    // 3. Register for all relevant system lifecycle notifications
    NSArray *notifNames = @[
        UIApplicationDidFinishLaunchingNotification,
        @"UISceneWillConnectNotification",
        @"UISceneDidActivateNotification",
        UIWindowDidBecomeKeyNotification,
        UIWindowDidBecomeVisibleNotification,
        UIApplicationDidBecomeActiveNotification
    ];
    
    for (NSString *name in notifNames) {
        [[NSNotificationCenter defaultCenter] addObserverForName:name
                                                          object:nil
                                                           queue:[NSOperationQueue mainQueue]
                                                      usingBlock:^(NSNotification * _Nonnull note) {
            [[AuthGateManager shared] enforceGate];
        }];
    }
    
    // 4. Repeated check during initial boot
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [[AuthGateManager shared] enforceGate];
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [[AuthGateManager shared] enforceGate];
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [[AuthGateManager shared] enforceGate];
    });
}
