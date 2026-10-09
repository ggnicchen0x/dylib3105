//
//  AuthGate.m
//  3105 Subscription & Access Control Gatekeeper
//  All-In-One Single-File Implementation for GitHub Actions CI/CD Build
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <sys/utsname.h>

#define AUTHGATE_VERSION @"1.1.3"
#define DEFAULT_SERVER_URL @"http://fi9.bot-hosting.cloud:25808"
#define DISCORD_URL @"https://discord.gg/KPJzd42rme"
#define KEYCHAIN_SERVICE @"com.authgate.session.service"
#define KEYCHAIN_ACCOUNT_KEY @"com.authgate.license.key"
#define KEYCHAIN_ACCOUNT_TOKEN @"com.authgate.session.token"
#define KEYCHAIN_ACCOUNT_HWID @"com.authgate.device.hwid"

#pragma mark - Keychain & Device Fingerprint Helper

@interface AuthGateSecurity : NSObject
+ (NSString *)getDeviceHWID;
+ (BOOL)saveLicenseKey:(NSString *)key sessionToken:(NSString *)token;
+ (nullable NSString *)getSavedLicenseKey;
+ (nullable NSString *)getSavedSessionToken;
+ (void)clearSession;
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

@end

#pragma mark - AuthGate View Controller (Full Native UI)

@interface AuthGateViewController : UIViewController <UITextFieldDelegate>
@property (nonatomic, copy) void (^onSuccess)(void);
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

- (UIStatusBarStyle)preferredStatusBarStyle {
    return UIStatusBarStyleLightContent;
}

- (void)setupUI {
    self.view.backgroundColor = [UIColor colorWithRed:0.05 green:0.06 blue:0.09 alpha:1.0]; // Deep Dark
    
    // Tap to dismiss keyboard
    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:self.view action:@selector(endEditing:)];
    [self.view addGestureRecognizer:tap];
    
    // Card Container
    _cardView = [[UIView alloc] init];
    _cardView.translatesAutoresizingMaskIntoConstraints = NO;
    _cardView.backgroundColor = [UIColor colorWithRed:0.09 green:0.11 blue:0.16 alpha:0.98];
    _cardView.layer.cornerRadius = 24.0;
    _cardView.layer.borderWidth = 1.0;
    _cardView.layer.borderColor = [UIColor colorWithRed:0.22 green:0.26 blue:0.38 alpha:0.5].CGColor;
    _cardView.layer.shadowColor = [UIColor blackColor].CGColor;
    _cardView.layer.shadowOpacity = 0.6;
    _cardView.layer.shadowOffset = CGSizeMake(0, 10);
    _cardView.layer.shadowRadius = 20.0;
    [self.view addSubview:_cardView];
    
    // Title
    _titleLabel = [[UILabel alloc] init];
    _titleLabel.translatesAutoresizingMaskIntoConstraints = NO;
    _titleLabel.text = @"3105";
    _titleLabel.textColor = [UIColor whiteColor];
    _titleLabel.font = [UIFont systemFontOfSize:34 weight:UIFontWeightHeavy];
    [_cardView addSubview:_titleLabel];
    
    // Version Badge
    _versionBadge = [[UILabel alloc] init];
    _versionBadge.translatesAutoresizingMaskIntoConstraints = NO;
    _versionBadge.text = [NSString stringWithFormat:@" v%@ ", AUTHGATE_VERSION];
    _versionBadge.textColor = [UIColor colorWithRed:0.35 green:0.85 blue:0.60 alpha:1.0];
    _versionBadge.backgroundColor = [UIColor colorWithRed:0.15 green:0.35 blue:0.25 alpha:0.4];
    _versionBadge.font = [UIFont systemFontOfSize:12 weight:UIFontWeightBold];
    _versionBadge.layer.cornerRadius = 6.0;
    _versionBadge.layer.masksToBounds = YES;
    [_cardView addSubview:_versionBadge];
    
    // Subtitle
    _subtitleLabel = [[UILabel alloc] init];
    _subtitleLabel.translatesAutoresizingMaskIntoConstraints = NO;
    _subtitleLabel.text = @"Subscription License Authentication";
    _subtitleLabel.textColor = [UIColor colorWithRed:0.60 green:0.65 blue:0.75 alpha:1.0];
    _subtitleLabel.font = [UIFont systemFontOfSize:14 weight:UIFontWeightMedium];
    [_cardView addSubview:_subtitleLabel];
    
    // Input Container
    UIView *inputBox = [[UIView alloc] init];
    inputBox.translatesAutoresizingMaskIntoConstraints = NO;
    inputBox.backgroundColor = [UIColor colorWithRed:0.06 green:0.07 blue:0.11 alpha:0.9];
    inputBox.layer.cornerRadius = 14.0;
    inputBox.layer.borderWidth = 1.0;
    inputBox.layer.borderColor = [UIColor colorWithRed:0.25 green:0.30 blue:0.42 alpha:0.6].CGColor;
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
                                                                      attributes:@{NSForegroundColorAttributeName: [UIColor colorWithWhite:0.4 alpha:1.0]}];
    [inputBox addSubview:_keyField];
    
    // Paste Button inside input box
    UIButton *pasteBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    pasteBtn.translatesAutoresizingMaskIntoConstraints = NO;
    [pasteBtn setTitle:@"Paste" forState:UIControlStateNormal];
    pasteBtn.titleLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightBold];
    [pasteBtn setTitleColor:[UIColor colorWithRed:0.35 green:0.65 blue:1.0 alpha:1.0] forState:UIControlStateNormal];
    [pasteBtn addTarget:self action:@selector(pasteKeyFromClipboard) forControlEvents:UIControlEventTouchUpInside];
    [inputBox addSubview:pasteBtn];
    
    // Activate Button
    _activateButton = [UIButton buttonWithType:UIButtonTypeCustom];
    _activateButton.translatesAutoresizingMaskIntoConstraints = NO;
    _activateButton.backgroundColor = [UIColor colorWithRed:0.22 green:0.46 blue:0.96 alpha:1.0];
    _activateButton.layer.cornerRadius = 14.0;
    _activateButton.layer.shadowColor = [UIColor colorWithRed:0.22 green:0.46 blue:0.96 alpha:0.4].CGColor;
    _activateButton.layer.shadowOpacity = 0.8;
    _activateButton.layer.shadowOffset = CGSizeMake(0, 6);
    _activateButton.layer.shadowRadius = 12.0;
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
    _statusLabel.textColor = [UIColor colorWithRed:0.95 green:0.40 blue:0.40 alpha:1.0];
    _statusLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    _statusLabel.numberOfLines = 0;
    _statusLabel.textAlignment = NSTextAlignmentCenter;
    [_cardView addSubview:_statusLabel];
    
    // Discord Button
    _discordButton = [UIButton buttonWithType:UIButtonTypeCustom];
    _discordButton.translatesAutoresizingMaskIntoConstraints = NO;
    [_discordButton setTitle:@"💬 Join Discord Community / Buy Key" forState:UIControlStateNormal];
    [_discordButton setTitleColor:[UIColor colorWithRed:0.45 green:0.55 blue:0.95 alpha:1.0] forState:UIControlStateNormal];
    _discordButton.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightSemibold];
    [_discordButton addTarget:self action:@selector(discordButtonTapped) forControlEvents:UIControlEventTouchUpInside];
    [_cardView addSubview:_discordButton];
    
    // Auto-Layout Constraints
    [NSLayoutConstraint activateConstraints:@[
        [_cardView.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor constant:-20],
        [_cardView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:24],
        [_cardView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-24],
        
        [_titleLabel.topAnchor constraintEqualToAnchor:_cardView.topAnchor constant:28],
        [_titleLabel.centerXAnchor constraintEqualToAnchor:_cardView.centerXAnchor constant:-30],
        
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
    _statusLabel.textColor = [UIColor colorWithRed:0.60 green:0.75 blue:0.95 alpha:1.0];
    _statusLabel.text = @"Verifying with license server...";
    
    NSString *hwid = [AuthGateSecurity getDeviceHWID];
    NSDictionary *body = @{
        @"key": key,
        @"license_key": key,
        @"device_hash": hwid,
        @"app_version": AUTHGATE_VERSION
    };
    
    NSString *serverURL = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"LicenseAPIURL"] ?: DEFAULT_SERVER_URL;
    NSString *loginURLStr = [NSString stringWithFormat:@"%@/api/v1/auth/login", [serverURL stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"/ "]]];
    
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:loginURLStr]];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [req setValue:@"application/json" forHTTPHeaderField:@"Accept"];
    [req setValue:@"3105-iOS/1.1.3" forHTTPHeaderField:@"User-Agent"];
    req.timeoutInterval = 15.0;
    req.HTTPBody = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
    
    [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            self->_isAuthenticating = NO;
            [self->_spinner stopAnimating];
            self->_activateButton.enabled = YES;
            self->_activateButton.alpha = 1.0;
            
            if (error || !data) {
                self->_statusLabel.textColor = [UIColor colorWithRed:0.95 green:0.40 blue:0.40 alpha:1.0];
                self->_statusLabel.text = @"Connection failed. Please check internet connection.";
                return;
            }
            
            NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            
            BOOL success = (httpResp.statusCode == 200 && json && ([json[@"success"] boolValue] || json[@"token"]));
            if (success) {
                NSString *token = json[@"token"] ?: @"SESSION_ACTIVE";
                [AuthGateSecurity saveLicenseKey:key sessionToken:token];
                
                self->_statusLabel.textColor = [UIColor colorWithRed:0.35 green:0.85 blue:0.60 alpha:1.0];
                self->_statusLabel.text = @"✓ Access Granted! Unlocking 3105...";
                
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    if (self.onSuccess) self.onSuccess();
                });
            } else {
                NSString *errMsg = json[@"detail"] ?: (json[@"message"] ?: @"Invalid or expired license key.");
                self->_statusLabel.textColor = [UIColor colorWithRed:0.95 green:0.40 blue:0.40 alpha:1.0];
                self->_statusLabel.text = [NSString stringWithFormat:@"❌ %@", errMsg];
            }
        });
    }] resume];
}

@end

#pragma mark - Master Gatekeeper Controller & Window Presenter

@interface AuthGateManager : NSObject
+ (instancetype)shared;
- (void)start;
- (void)dismissGate;
@end

@implementation AuthGateManager {
    UIWindow *_gateWindow;
    BOOL _unlocked;
}

+ (instancetype)shared {
    static AuthGateManager *inst = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ inst = [[AuthGateManager alloc] init]; });
    return inst;
}

- (void)start {
    if (_unlocked) return;
    
    // Check if valid token exists in Keychain
    NSString *savedToken = [AuthGateSecurity getSavedSessionToken];
    NSString *savedKey = [AuthGateSecurity getSavedLicenseKey];
    
    [self presentGateWindow];
    
    if (savedToken && savedKey) {
        // Perform silent validation
        NSString *serverURL = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"LicenseAPIURL"] ?: DEFAULT_SERVER_URL;
        NSString *valURL = [NSString stringWithFormat:@"%@/api/v1/auth/validate", [serverURL stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"/ "]]];
        
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:valURL]];
        req.HTTPMethod = @"POST";
        [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
        req.timeoutInterval = 10.0;
        req.HTTPBody = [NSJSONSerialization dataWithJSONObject:@{@"token": savedToken, @"device_hash": [AuthGateSecurity getDeviceHWID], @"app_version": AUTHGATE_VERSION} options:0 error:nil];
        
        [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
            NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
            if (httpResp.statusCode == 200) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self dismissGate];
                });
            }
        }] resume];
    }
}

- (void)presentGateWindow {
    if (_gateWindow) return;
    
    UIWindowScene *scene = nil;
    if (@available(iOS 13.0, *)) {
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
            if ([s isKindOfClass:[UIWindowScene class]] && s.activationState == UISceneActivationStateForegroundActive) {
                scene = (UIWindowScene *)s;
                break;
            }
        }
    }
    
    if (scene) {
        _gateWindow = [[UIWindow alloc] initWithWindowScene:scene];
    } else {
        _gateWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    }
    
    _gateWindow.windowLevel = UIWindowLevelAlert + 1000.0;
    AuthGateViewController *vc = [[AuthGateViewController alloc] init];
    __weak typeof(self) weakSelf = self;
    vc.onSuccess = ^{
        [weakSelf dismissGate];
    };
    _gateWindow.rootViewController = vc;
    _gateWindow.hidden = NO;
    [_gateWindow makeKeyAndVisible];
}

- (void)dismissGate {
    _unlocked = YES;
    if (!_gateWindow) return;
    
    [UIView animateWithDuration:0.4 animations:^{
        self->_gateWindow.alpha = 0.0;
        self->_gateWindow.transform = CGAffineTransformMakeScale(1.08, 1.08);
    } completion:^(BOOL finished) {
        self->_gateWindow.hidden = YES;
        self->_gateWindow.rootViewController = nil;
        self->_gateWindow = nil;
    }];
}

@end

#pragma mark - Constructor & Lifecycle Hook

__attribute__((constructor))
static void AuthGateInit(void) {
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                      object:nil
                                                       queue:[NSOperationQueue mainQueue]
                                                  usingBlock:^(NSNotification * _Nonnull note) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [[AuthGateManager shared] start];
        });
    }];
    
    [[NSNotificationCenter defaultCenter] addObserverForName:UIWindowDidBecomeKeyNotification
                                                      object:nil
                                                       queue:[NSOperationQueue mainQueue]
                                                  usingBlock:^(NSNotification * _Nonnull note) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [[AuthGateManager shared] start];
        });
    }];
}
