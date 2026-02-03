// FakeInfo-UIDevice Tweak - FIXED VERSION
// Fixed: MSHookFunction now saves original function pointers to prevent infinite recursion

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <substrate.h>
#import <sys/utsname.h>
#import <sys/sysctl.h>
#import <ifaddrs.h>
#import <arpa/inet.h>
#import <netinet/in.h>
#import <dlfcn.h>
#import <execinfo.h>
#import <sys/stat.h>

// MARK: - Original Function Pointers (CRITICAL FIX)
static int (*orig_sysctlbyname_ptr)(const char *, void *, size_t *, void *, size_t) = NULL;
static int (*orig_uname_ptr)(struct utsname *) = NULL;
static int (*orig_getifaddrs_ptr)(struct ifaddrs **) = NULL;
static int (*orig_stat_ptr)(const char *, struct stat *) = NULL;
static int (*orig_access_ptr)(const char *, int) = NULL;
static FILE* (*orig_fopen_ptr)(const char *, const char *) = NULL;

// MARK: - Global Variables & Forward Declarations
static UIWindow *settingsWindow = nil;
static BOOL hasShownSettings = NO;

void ShowSettingsUI(void);
void SetupGestureRecognizer(void);

// MARK: - Logging & Anti-Crash
void SafeLog(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    NSLog(@"[FakeTweak] %@", msg);
}

void CrashHandler(int sig) {
    SafeLog(@"=== SIGNAL CRASH DETECTED: %d ===", sig);
    void *callstack[128];
    int frames = backtrace(callstack, 128);
    char **symbols = backtrace_symbols(callstack, frames);
    for (int i = 0; i < frames; i++) {
        SafeLog(@"Frame %d: %s", i, symbols[i]);
    }
    free(symbols);
    signal(sig, SIG_DFL);
    raise(sig);
}

// MARK: - Settings Storage
@interface FakeSettings : NSObject
+ (instancetype)shared;
- (void)loadSettings;
- (void)saveSettings;
- (void)resetSettings;
@property (nonatomic, strong) NSMutableDictionary *settings;
@property (nonatomic, strong) NSMutableDictionary *toggles;
@property (nonatomic, strong) NSDictionary *originalValues;
@end

@implementation FakeSettings
+ (instancetype)shared {
    static FakeSettings *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[FakeSettings alloc] init];
    });
    return instance;
}

- (instancetype)init {
    if (self = [super init]) {
        [self loadOriginalValues];
        [self loadSettings];
    }
    return self;
}

- (void)loadOriginalValues {
    UIDevice *device = [UIDevice currentDevice];
    NSBundle *bundle = [NSBundle mainBundle];
    struct utsname systemInfo;
    uname(&systemInfo);

    char osrelease[256];
    size_t size = sizeof(osrelease);
    if (sysctlbyname("kern.osrelease", osrelease, &size, NULL, 0) != 0) {
        osrelease[0] = '\0';
    }

    self.originalValues = @{
        @"systemVersion": device.systemVersion ?: @"Unknown",
        @"deviceModel": [NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding] ?: @"Unknown",
        @"deviceName": device.name ?: @"Unknown",
        @"identifierForVendor": device.identifierForVendor.UUIDString ?: @"Unknown",
        @"bundleIdentifier": bundle.bundleIdentifier ?: @"Unknown",
        @"appVersion": [bundle.infoDictionary objectForKey:@"CFBundleShortVersionString"] ?: @"Unknown",
        @"bundleVersion": [bundle.infoDictionary objectForKey:@"CFBundleVersion"] ?: @"Unknown",
        @"displayName": [bundle.infoDictionary objectForKey:@"CFBundleDisplayName"] ?: @"Unknown",
        @"darwinVersion": [NSString stringWithCString:osrelease encoding:NSUTF8StringEncoding] ?: @"Unknown",
        @"wifiIP": @"192.168.1.100"
    };
}

- (void)loadSettings {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    self.settings = [[defaults objectForKey:@"FakeSettings"] mutableCopy] ?: [NSMutableDictionary dictionary];
    self.toggles = [[defaults objectForKey:@"FakeToggles"] mutableCopy] ?: [NSMutableDictionary dictionary];
    if (!self.toggles[@"jailbreak"]) self.toggles[@"jailbreak"] = @NO;
}

- (void)saveSettings {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults setObject:self.settings forKey:@"FakeSettings"];
    [defaults setObject:self.toggles forKey:@"FakeToggles"];
    [defaults synchronize];
}

- (void)resetSettings {
    self.settings = [NSMutableDictionary dictionary];
    self.toggles = [NSMutableDictionary dictionary];
    [self saveSettings];
}

- (BOOL)isEnabled:(NSString *)key {
    return [self.toggles[key] boolValue];
}

- (NSString *)valueForKey:(NSString *)key {
    return self.settings[key] ?: self.originalValues[key] ?: @"N/A";
}
@end

// MARK: - Settings UI (Forward declaration - full implementation below)
@interface FakeSettingsViewController : UIViewController <UITableViewDataSource, UITableViewDelegate>
@property (nonatomic, strong) UITableView *tableView;
@property (nonatomic, strong) NSArray *settingsKeys;
@property (nonatomic, strong) NSDictionary *settingsLabels;
@end

// MARK: - Gesture Handler
@interface GestureHandler : NSObject
- (void)handleTripleFingerTap:(UITapGestureRecognizer *)gesture;
- (void)handleFourFingerLongPress:(UILongPressGestureRecognizer *)gesture;
- (void)handleFourFingerShortPress:(UILongPressGestureRecognizer *)gesture;
@end

@implementation GestureHandler
- (void)handleTripleFingerTap:(UITapGestureRecognizer *)gesture {
    if (!hasShownSettings && !settingsWindow) {
        ShowSettingsUI();
    }
}

- (void)handleFourFingerLongPress:(UILongPressGestureRecognizer *)gesture {
    if (gesture.state == UIGestureRecognizerStateBegan) {
        SafeLog(@"Four finger long press detected - showing UI");
        ShowSettingsUI();
        if (@available(iOS 10.0, *)) {
            UIImpactFeedbackGenerator *feedback = [[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleHeavy];
            [feedback impactOccurred];
        }
    }
}

- (void)handleFourFingerShortPress:(UILongPressGestureRecognizer *)gesture {
    if (gesture.state == UIGestureRecognizerStateBegan) {
        SafeLog(@"Four finger short press detected - showing UI");
        ShowSettingsUI();
        if (@available(iOS 10.0, *)) {
            UIImpactFeedbackGenerator *feedback = [[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleMedium];
            [feedback impactOccurred];
        }
    }
}
@end

static GestureHandler *gestureHandler = nil;
static UITapGestureRecognizer *tripleFingerGesture = nil;
static UILongPressGestureRecognizer *fourFingerLongPress = nil;
static UILongPressGestureRecognizer *fourFingerShortPress = nil;

// MARK: - FakeSettingsViewController Implementation
@implementation FakeSettingsViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.9];
    
    self.settingsKeys = @[@"systemVersion", @"deviceModel", @"deviceName", @"identifierForVendor", 
                          @"bundleIdentifier", @"appVersion", @"bundleVersion", @"displayName", 
                          @"darwinVersion", @"wifiIP", @"jailbreak"];
    
    self.settingsLabels = @{
        @"systemVersion": @"iOS Version",
        @"deviceModel": @"Device Model",
        @"deviceName": @"Device Name",
        @"identifierForVendor": @"Vendor ID",
        @"bundleIdentifier": @"Bundle ID",
        @"appVersion": @"App Version",
        @"bundleVersion": @"Build Version",
        @"displayName": @"Display Name",
        @"darwinVersion": @"Darwin Version",
        @"wifiIP": @"WiFi IP",
        @"jailbreak": @"Hide Jailbreak"
    };
    
    // Title label
    UILabel *titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(0, 50, self.view.bounds.size.width, 40)];
    titleLabel.text = @"🎭 FakeInfo Settings";
    titleLabel.textColor = [UIColor whiteColor];
    titleLabel.textAlignment = NSTextAlignmentCenter;
    titleLabel.font = [UIFont boldSystemFontOfSize:20];
    [self.view addSubview:titleLabel];
    
    // Close button
    UIButton *closeBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    closeBtn.frame = CGRectMake(self.view.bounds.size.width - 60, 50, 50, 40);
    [closeBtn setTitle:@"✕" forState:UIControlStateNormal];
    [closeBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    closeBtn.titleLabel.font = [UIFont systemFontOfSize:24];
    [closeBtn addTarget:self action:@selector(closeSettings) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:closeBtn];
    
    // TableView
    self.tableView = [[UITableView alloc] initWithFrame:CGRectMake(10, 100, self.view.bounds.size.width - 20, self.view.bounds.size.height - 180) style:UITableViewStyleGrouped];
    self.tableView.delegate = self;
    self.tableView.dataSource = self;
    self.tableView.backgroundColor = [UIColor clearColor];
    self.tableView.separatorColor = [[UIColor whiteColor] colorWithAlphaComponent:0.3];
    [self.view addSubview:self.tableView];
    
    // Save button
    UIButton *saveBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    saveBtn.frame = CGRectMake(20, self.view.bounds.size.height - 70, self.view.bounds.size.width - 40, 50);
    saveBtn.backgroundColor = [UIColor systemBlueColor];
    saveBtn.layer.cornerRadius = 10;
    [saveBtn setTitle:@"💾 Save Settings" forState:UIControlStateNormal];
    [saveBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    saveBtn.titleLabel.font = [UIFont boldSystemFontOfSize:18];
    [saveBtn addTarget:self action:@selector(saveAndClose) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:saveBtn];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 2;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (section == 0) return self.settingsKeys.count;
    return 1; // Reset button
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (section == 0) return @"Fake Values";
    return @"Actions";
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    if (indexPath.section == 1) {
        UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:@"reset"];
        cell.textLabel.text = @"🔄 Reset All Settings";
        cell.textLabel.textColor = [UIColor systemRedColor];
        cell.textLabel.textAlignment = NSTextAlignmentCenter;
        cell.backgroundColor = [[UIColor whiteColor] colorWithAlphaComponent:0.1];
        return cell;
    }
    
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:@"setting"];
    NSString *key = self.settingsKeys[indexPath.row];
    FakeSettings *settings = [FakeSettings shared];
    
    cell.textLabel.text = self.settingsLabels[key];
    cell.textLabel.textColor = [UIColor whiteColor];
    cell.detailTextLabel.text = [settings valueForKey:key];
    cell.detailTextLabel.textColor = [[UIColor whiteColor] colorWithAlphaComponent:0.7];
    cell.backgroundColor = [[UIColor whiteColor] colorWithAlphaComponent:0.1];
    
    // Toggle switch
    UISwitch *toggle = [[UISwitch alloc] init];
    toggle.on = [settings isEnabled:key];
    toggle.tag = indexPath.row;
    [toggle addTarget:self action:@selector(toggleChanged:) forControlEvents:UIControlEventValueChanged];
    cell.accessoryView = toggle;
    
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    
    if (indexPath.section == 1) {
        [[FakeSettings shared] resetSettings];
        [self.tableView reloadData];
        return;
    }
    
    NSString *key = self.settingsKeys[indexPath.row];
    if ([key isEqualToString:@"jailbreak"]) return;
    
    [self showEditAlertForKey:key];
}

- (void)showEditAlertForKey:(NSString *)key {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:self.settingsLabels[key]
                                                                  message:@"Enter new value"
                                                           preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.text = [[FakeSettings shared] valueForKey:key];
        textField.placeholder = @"New value";
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Save" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSString *newValue = alert.textFields.firstObject.text;
        if (newValue.length > 0) {
            [FakeSettings shared].settings[key] = newValue;
            [self.tableView reloadData];
        }
    }]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)toggleChanged:(UISwitch *)toggle {
    NSString *key = self.settingsKeys[toggle.tag];
    [FakeSettings shared].toggles[key] = @(toggle.on);
}

- (void)saveAndClose {
    [[FakeSettings shared] saveSettings];
    [self closeSettings];
}

- (void)closeSettings {
    if (settingsWindow) {
        settingsWindow.hidden = YES;
        settingsWindow = nil;
        hasShownSettings = NO;
    }
}

@end

void SetupGestureRecognizer() {
    dispatch_async(dispatch_get_main_queue(), ^{
        @autoreleasepool {
            UIWindow *keyWindow = nil;
            if (@available(iOS 13.0, *)) {
                for (UIWindowScene *windowScene in [UIApplication sharedApplication].connectedScenes) {
                    if (windowScene.activationState == UISceneActivationStateForegroundActive) {
                        keyWindow = windowScene.windows.firstObject;
                        break;
                    }
                }
            }
            if (!keyWindow) {
                #pragma clang diagnostic push
                #pragma clang diagnostic ignored "-Wdeprecated-declarations"
                keyWindow = [UIApplication sharedApplication].keyWindow;
                #pragma clang diagnostic pop
            }
            if (!keyWindow) {
                NSArray *windows = [UIApplication sharedApplication].windows;
                for (UIWindow *window in windows) {
                    if (window) { keyWindow = window; break; }
                }
            }
            if (!keyWindow) {
                SafeLog(@"Warning: Could not find any window to attach gesture recognizer.");
                return;
            }

            if (!gestureHandler) gestureHandler = [[GestureHandler alloc] init];

            if (!tripleFingerGesture) {
                tripleFingerGesture = [[UITapGestureRecognizer alloc] initWithTarget:gestureHandler action:@selector(handleTripleFingerTap:)];
                tripleFingerGesture.numberOfTapsRequired = 2;
                tripleFingerGesture.numberOfTouchesRequired = 4;
                [keyWindow addGestureRecognizer:tripleFingerGesture];
            }

            if (!fourFingerLongPress) {
                fourFingerLongPress = [[UILongPressGestureRecognizer alloc] initWithTarget:gestureHandler action:@selector(handleFourFingerLongPress:)];
                fourFingerLongPress.numberOfTouchesRequired = 4;
                fourFingerLongPress.minimumPressDuration = 1.5;
                [keyWindow addGestureRecognizer:fourFingerLongPress];
            }

            if (!fourFingerShortPress) {
                fourFingerShortPress = [[UILongPressGestureRecognizer alloc] initWithTarget:gestureHandler action:@selector(handleFourFingerShortPress:)];
                fourFingerShortPress.numberOfTouchesRequired = 4;
                fourFingerShortPress.minimumPressDuration = 0.3;
                [keyWindow addGestureRecognizer:fourFingerShortPress];
            }
        }
    });
}

void ShowSettingsUI() {
    if (settingsWindow) {
        settingsWindow.hidden = YES;
        settingsWindow = nil;
        hasShownSettings = NO;
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        @autoreleasepool {
            settingsWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
            settingsWindow.windowLevel = UIWindowLevelAlert + 50;
            settingsWindow.backgroundColor = [UIColor clearColor];
            FakeSettingsViewController *settingsVC = [[FakeSettingsViewController alloc] init];
            settingsWindow.rootViewController = settingsVC;
            [settingsWindow makeKeyAndVisible];
            SafeLog(@"Settings UI presented.");
        }
    });
}

// MARK: - FIXED Fake C Functions (using saved original pointers)

int fake_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    @try {
        FakeSettings *settings = [FakeSettings shared];
        if ([settings isEnabled:@"deviceModel"] && strcmp(name, "hw.machine") == 0) {
            const char *val = [[settings valueForKey:@"deviceModel"] UTF8String];
            size_t len = strlen(val) + 1;
            if (oldp && oldlenp && *oldlenp >= len) {
                strcpy((char *)oldp, val);
                *oldlenp = len;
                return 0;
            }
        }
        if ([settings isEnabled:@"darwinVersion"] && strcmp(name, "kern.osrelease") == 0) {
            const char *val = [[settings valueForKey:@"darwinVersion"] UTF8String];
            size_t len = strlen(val) + 1;
            if (oldp && oldlenp && *oldlenp >= len) {
                strcpy((char *)oldp, val);
                *oldlenp = len;
                return 0;
            }
        }
    } @catch(NSException *e) {
        SafeLog(@"[CRASH][sysctlbyname]: %@", e.reason);
    }
    // FIXED: Call original via saved pointer
    if (orig_sysctlbyname_ptr) return orig_sysctlbyname_ptr(name, oldp, oldlenp, newp, newlen);
    return -1;
}

int fake_uname(struct utsname *name) {
    // FIXED: Call original via saved pointer
    int ret = orig_uname_ptr ? orig_uname_ptr(name) : -1;
    if (ret != 0) return ret;
    
    @try {
        FakeSettings *settings = [FakeSettings shared];
        if ([settings isEnabled:@"deviceModel"]) {
            NSString *fakeModel = [settings valueForKey:@"deviceModel"];
            if (fakeModel) {
                strncpy(name->machine, [fakeModel UTF8String], sizeof(name->machine) - 1);
                name->machine[sizeof(name->machine) - 1] = '\0';
            }
        }
        if ([settings isEnabled:@"darwinVersion"]) {
            NSString *fakeDarwin = [settings valueForKey:@"darwinVersion"];
            if (fakeDarwin) {
                strncpy(name->release, [fakeDarwin UTF8String], sizeof(name->release) - 1);
                name->release[sizeof(name->release) - 1] = '\0';
            }
        }
    } @catch(NSException *e) {
        SafeLog(@"[CRASH][uname]: %@", e.reason);
    }
    return ret;
}

int fake_getifaddrs(struct ifaddrs **ifap) {
    // FIXED: Call original via saved pointer
    int ret = orig_getifaddrs_ptr ? orig_getifaddrs_ptr(ifap) : -1;
    if (ret != 0 || !ifap || !*ifap) return ret;
    
    FakeSettings *settings = [FakeSettings shared];
    if ([settings isEnabled:@"wifiIP"]) {
        @try {
            struct ifaddrs *ifa = *ifap;
            while (ifa) {
                if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET && strcmp(ifa->ifa_name, "en0") == 0) {
                    struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
                    const char* fakeIP = [[settings valueForKey:@"wifiIP"] UTF8String];
                    inet_pton(AF_INET, fakeIP, &(addr->sin_addr));
                }
                ifa = ifa->ifa_next;
            }
        } @catch(NSException *e) {
            SafeLog(@"[CRASH][getifaddrs]: %@", e.reason);
        }
    }
    return ret;
}

int fake_stat(const char *path, struct stat *buf) {
    FakeSettings *settings = [FakeSettings shared];
    if ([settings isEnabled:@"jailbreak"] && path) {
        if (strstr(path, "Cydia") || strstr(path, "bash") || strstr(path, "apt") || strstr(path, "MobileSubstrate")) {
            errno = ENOENT;
            return -1;
        }
    }
    // FIXED: Call original via saved pointer
    return orig_stat_ptr ? orig_stat_ptr(path, buf) : -1;
}

int fake_access(const char *path, int amode) {
    FakeSettings *settings = [FakeSettings shared];
    if ([settings isEnabled:@"jailbreak"] && path) {
        if (strstr(path, "Cydia") || strstr(path, "bash") || strstr(path, "apt") || strstr(path, "MobileSubstrate")) {
            return -1;
        }
    }
    // FIXED: Call original via saved pointer
    return orig_access_ptr ? orig_access_ptr(path, amode) : -1;
}

FILE* fake_fopen(const char *path, const char *mode) {
    FakeSettings *settings = [FakeSettings shared];
    if ([settings isEnabled:@"jailbreak"] && path) {
        if (strstr(path, "Cydia") || strstr(path, "bash") || strstr(path, "apt") || strstr(path, "MobileSubstrate")) {
            return NULL;
        }
    }
    // FIXED: Call original via saved pointer
    return orig_fopen_ptr ? orig_fopen_ptr(path, mode) : NULL;
}

// MARK: - Fake UIDevice Hooks
%hook UIDevice
- (NSString *)systemVersion {
    @try {
        FakeSettings *settings = [FakeSettings shared];
        if ([settings isEnabled:@"systemVersion"]) return [settings valueForKey:@"systemVersion"];
    } @catch(NSException *e) { SafeLog(@"[CRASH] UIDevice.systemVersion: %@", e.reason); }
    return %orig;
}

- (NSString *)model {
    @try {
        FakeSettings *settings = [FakeSettings shared];
        if ([settings isEnabled:@"deviceModel"]) return [settings valueForKey:@"deviceModel"];
    } @catch(NSException *e) { SafeLog(@"[CRASH] UIDevice.model: %@", e.reason); }
    return %orig;
}

- (NSString *)name {
    @try {
        FakeSettings *settings = [FakeSettings shared];
        if ([settings isEnabled:@"deviceName"]) return [settings valueForKey:@"deviceName"];
    } @catch(NSException *e) { SafeLog(@"[CRASH] UIDevice.name: %@", e.reason); }
    return %orig;
}

- (NSUUID *)identifierForVendor {
    @try {
        FakeSettings *settings = [FakeSettings shared];
        if ([settings isEnabled:@"identifierForVendor"]) {
            return [[NSUUID alloc] initWithUUIDString:[settings valueForKey:@"identifierForVendor"]];
        }
    } @catch(NSException *e) { SafeLog(@"[CRASH] UIDevice.identifierForVendor: %@", e.reason); }
    return %orig;
}
%end

// MARK: - Fake NSBundle Hooks
%hook NSBundle
- (NSString *)bundleIdentifier {
    @try {
        if (self == [NSBundle mainBundle]) {
            FakeSettings *settings = [FakeSettings shared];
            if ([settings isEnabled:@"bundleIdentifier"]) return [settings valueForKey:@"bundleIdentifier"];
        }
    } @catch(NSException *e) { SafeLog(@"[CRASH] NSBundle.bundleIdentifier: %@", e.reason); }
    return %orig;
}

- (NSDictionary *)infoDictionary {
    @try {
        NSDictionary *origDict = %orig;
        NSMutableDictionary *dict = origDict ? [origDict mutableCopy] : [NSMutableDictionary dictionary];
        FakeSettings *settings = [FakeSettings shared];
        if ([settings isEnabled:@"appVersion"]) dict[@"CFBundleShortVersionString"] = [settings valueForKey:@"appVersion"];
        if ([settings isEnabled:@"bundleVersion"]) dict[@"CFBundleVersion"] = [settings valueForKey:@"bundleVersion"];
        if ([settings isEnabled:@"displayName"]) dict[@"CFBundleDisplayName"] = [settings valueForKey:@"displayName"];
        return dict;
    } @catch(NSException *e) { SafeLog(@"[CRASH] NSBundle.infoDictionary: %@", e.reason); }
    return %orig;
}
%end

// MARK: - Fake NSProcessInfo Hook
%hook NSProcessInfo
- (NSString *)operatingSystemVersionString {
    @try {
        FakeSettings *settings = [FakeSettings shared];
        if ([settings isEnabled:@"systemVersion"]) {
            return [NSString stringWithFormat:@"Version %@ (Build %@)",
                   [settings valueForKey:@"systemVersion"],
                   [settings valueForKey:@"bundleVersion"] ?: @"UnknownBuild"];
        }
    } @catch(NSException *e) { SafeLog(@"[CRASH] NSProcessInfo.operatingSystemVersionString: %@", e.reason); }
    return %orig;
}
%end

// MARK: - Fake Jailbreak Detection
%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    @try {
        FakeSettings *settings = [FakeSettings shared];
        if ([settings isEnabled:@"jailbreak"]) {
            NSArray *jbPaths = @[@"/Applications/Cydia.app", @"/usr/sbin/sshd", @"/bin/bash", @"/etc/apt", @"/private/var/lib/apt/", @"/Library/MobileSubstrate/MobileSubstrate.dylib"];
            if ([jbPaths containsObject:path]) return NO;
        }
    } @catch(NSException *e) { SafeLog(@"[CRASH] NSFileManager.fileExistsAtPath: %@", e.reason); }
    return %orig;
}
%end

// MARK: - Tweak Initialization (FIXED)
%ctor {
    @autoreleasepool {
        signal(SIGSEGV, CrashHandler);
        signal(SIGBUS, CrashHandler);
        signal(SIGABRT, CrashHandler);

        [FakeSettings shared];

        void *handle = dlopen(NULL, RTLD_NOW);
        if (handle) {
            void *ptr_sysctlbyname = dlsym(handle, "sysctlbyname");
            void *ptr_uname = dlsym(handle, "uname");
            void *ptr_getifaddrs = dlsym(handle, "getifaddrs");
            void *ptr_stat = dlsym(handle, "stat");
            void *ptr_access = dlsym(handle, "access");
            void *ptr_fopen = dlsym(handle, "fopen");

            // FIXED: Save original pointers (3rd parameter is NOT NULL anymore)
            if (ptr_sysctlbyname) MSHookFunction(ptr_sysctlbyname, (void *)&fake_sysctlbyname, (void **)&orig_sysctlbyname_ptr);
            if (ptr_uname) MSHookFunction(ptr_uname, (void *)&fake_uname, (void **)&orig_uname_ptr);
            if (ptr_getifaddrs) MSHookFunction(ptr_getifaddrs, (void *)&fake_getifaddrs, (void **)&orig_getifaddrs_ptr);
            if (ptr_stat) MSHookFunction(ptr_stat, (void *)&fake_stat, (void **)&orig_stat_ptr);
            if (ptr_access) MSHookFunction(ptr_access, (void *)&fake_access, (void **)&orig_access_ptr);
            if (ptr_fopen) MSHookFunction(ptr_fopen, (void *)&fake_fopen, (void **)&orig_fopen_ptr);

            dlclose(handle);
        } else {
            SafeLog(@"Error opening handle for current executable: %s", dlerror());
        }

        SafeLog(@"🎭 [FakeTweak] FIXED VERSION LOADED! Created by @thanhdo1110");
        
        // Delay to ensure app is ready, then show startup alert
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2.0 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            SetupGestureRecognizer();
            
            // Show startup alert to confirm tweak is working
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"🎭 FakeInfo Loaded!"
                                                                          message:@"Tweak đã được inject thành công!\n\n• Tap 'Open Settings' để mở cài đặt\n• Hoặc dùng 4 ngón giữ 1.5s"
                                                                   preferredStyle:UIAlertControllerStyleAlert];
            
            [alert addAction:[UIAlertAction actionWithTitle:@"Open Settings" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                ShowSettingsUI();
            }]];
            
            [alert addAction:[UIAlertAction actionWithTitle:@"Đóng" style:UIAlertActionStyleCancel handler:nil]];
            
            // Find top view controller to present alert
            UIViewController *topVC = nil;
            if (@available(iOS 13.0, *)) {
                for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
                    if (scene.activationState == UISceneActivationStateForegroundActive) {
                        for (UIWindow *window in scene.windows) {
                            if (window.isKeyWindow) {
                                topVC = window.rootViewController;
                                while (topVC.presentedViewController) {
                                    topVC = topVC.presentedViewController;
                                }
                                break;
                            }
                        }
                    }
                }
            }
            if (!topVC) {
                #pragma clang diagnostic push
                #pragma clang diagnostic ignored "-Wdeprecated-declarations"
                topVC = [UIApplication sharedApplication].keyWindow.rootViewController;
                while (topVC.presentedViewController) {
                    topVC = topVC.presentedViewController;
                }
                #pragma clang diagnostic pop
            }
            
            if (topVC) {
                [topVC presentViewController:alert animated:YES completion:nil];
            }
        });
    }
}

