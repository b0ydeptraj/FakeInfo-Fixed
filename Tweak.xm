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
#import <Security/Security.h>
#import <AdSupport/AdSupport.h>
#import <CoreTelephony/CTCarrier.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <sys/sysctl.h>
#import <mach/mach.h>

// MARK: - Original Function Pointers (CRITICAL FIX)
static int (*orig_sysctlbyname_ptr)(const char *, void *, size_t *, void *, size_t) = NULL;
static int (*orig_uname_ptr)(struct utsname *) = NULL;
static int (*orig_getifaddrs_ptr)(struct ifaddrs **) = NULL;
static int (*orig_stat_ptr)(const char *, struct stat *) = NULL;
static int (*orig_access_ptr)(const char *, int) = NULL;
static FILE* (*orig_fopen_ptr)(const char *, const char *) = NULL;

// Keychain hooks
static OSStatus (*orig_SecItemCopyMatching_ptr)(CFDictionaryRef query, CFTypeRef *result) = NULL;
static OSStatus (*orig_SecItemAdd_ptr)(CFDictionaryRef attributes, CFTypeRef *result) = NULL;
static OSStatus (*orig_SecItemDelete_ptr)(CFDictionaryRef query) = NULL;

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
                          @"idfa", @"locale", @"timezone", @"carrier",
                          @"bundleIdentifier", @"appVersion", @"bundleVersion", @"displayName", 
                          @"darwinVersion", @"wifiIP", @"bootTime", @"jailbreak", @"keychain"];
    
    self.settingsLabels = @{
        @"systemVersion": @"📱 iOS Version",
        @"deviceModel": @"📲 Device Model",
        @"deviceName": @"📛 Device Name",
        @"identifierForVendor": @"🔑 Vendor ID (UUID)",
        @"idfa": @"📺 Advertising ID (IDFA)",
        @"locale": @"🌍 Language/Region",
        @"timezone": @"🕐 Timezone",
        @"carrier": @"📶 Carrier Name",
        @"bundleIdentifier": @"📦 Bundle ID",
        @"appVersion": @"🏷️ App Version",
        @"bundleVersion": @"🔢 Build Version",
        @"displayName": @"✏️ Display Name",
        @"darwinVersion": @"⚙️ Darwin Version",
        @"wifiIP": @"📡 WiFi IP",
        @"bootTime": @"⏰ Boot Time (Fresh)",
        @"jailbreak": @"🔓 Hide Jailbreak",
        @"keychain": @"🔐 Block Keychain"
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
    return 2; // Random All + Reset button
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (section == 0) return @"Fake Values";
    return @"Quick Actions";
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    if (indexPath.section == 1) {
        UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:@"action"];
        cell.textLabel.textAlignment = NSTextAlignmentCenter;
        cell.backgroundColor = [[UIColor whiteColor] colorWithAlphaComponent:0.1];
        
        if (indexPath.row == 0) {
            cell.textLabel.text = @"🎲 Random All (Real Device Data)";
            cell.textLabel.textColor = [UIColor systemGreenColor];
        } else {
            cell.textLabel.text = @"🔄 Reset All Settings";
            cell.textLabel.textColor = [UIColor systemRedColor];
        }
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
        if (indexPath.row == 0) {
            [self randomAllSettings];
        } else {
            [[FakeSettings shared] resetSettings];
        }
        [self.tableView reloadData];
        return;
    }
    
    NSString *key = self.settingsKeys[indexPath.row];
    if ([key isEqualToString:@"jailbreak"] || [key isEqualToString:@"keychain"]) return;
    
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

// ============================================================================
// MARK: - Online Device Database from ipsw.me API
// ============================================================================

// Cache key constants
static NSString *const kCachedDevicesKey = @"FakeInfo_CachedDevices";
static NSString *const kCacheTimestampKey = @"FakeInfo_CacheTimestamp";
static const NSTimeInterval kCacheExpiration = 24 * 60 * 60; // 24 hours

// Darwin version mapping based on iOS major version
- (NSString *)darwinVersionForIOS:(NSString *)iosVersion {
    if (!iosVersion) return @"24.0.0";
    
    NSArray *parts = [iosVersion componentsSeparatedByString:@"."];
    if (parts.count == 0) return @"24.0.0";
    
    int major = [parts[0] intValue];
    NSString *minor = parts.count > 1 ? parts[1] : @"0";
    
    // iOS major version + 6 = Darwin major version
    // iOS 18 -> Darwin 24, iOS 17 -> Darwin 23, etc.
    int darwinMajor = major + 6;
    
    return [NSString stringWithFormat:@"%d.%@.0", darwinMajor, minor];
}

// Check if cache is still valid
- (BOOL)isCacheValid {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSDate *timestamp = [defaults objectForKey:kCacheTimestampKey];
    if (!timestamp) return NO;
    
    NSTimeInterval age = [[NSDate date] timeIntervalSinceDate:timestamp];
    return age < kCacheExpiration;
}

// Get cached devices
- (NSArray *)getCachedDevices {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    return [defaults arrayForKey:kCachedDevicesKey];
}

// Save devices to cache
- (void)cacheDevices:(NSArray *)devices {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults setObject:devices forKey:kCachedDevicesKey];
    [defaults setObject:[NSDate date] forKey:kCacheTimestampKey];
    [defaults synchronize];
    SafeLog(@"📦 Cached %lu devices from API", (unsigned long)devices.count);
}

// Fetch devices from ipsw.me API
- (void)fetchDevicesFromAPI:(void(^)(NSArray *devices, NSError *error))completion {
    NSURL *url = [NSURL URLWithString:@"https://api.ipsw.me/v4/devices"];
    
    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithURL:url 
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            if (error) {
                SafeLog(@"❌ API fetch error: %@", error.localizedDescription);
                completion(nil, error);
                return;
            }
            
            NSError *jsonError;
            NSArray *allDevices = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
            if (jsonError) {
                SafeLog(@"❌ JSON parse error: %@", jsonError.localizedDescription);
                completion(nil, jsonError);
                return;
            }
            
            // Filter only iPhones (identifier starts with "iPhone")
            NSMutableArray *iPhones = [NSMutableArray array];
            for (NSDictionary *device in allDevices) {
                NSString *identifier = device[@"identifier"];
                if ([identifier hasPrefix:@"iPhone"]) {
                    [iPhones addObject:@{
                        @"model": identifier,
                        @"name": device[@"name"]
                    }];
                }
            }
            
            SafeLog(@"✅ Fetched %lu iPhones from API", (unsigned long)iPhones.count);
            completion(iPhones, nil);
        }];
    [task resume];
}

// Fetch firmware info for a specific device
- (void)fetchFirmwareForDevice:(NSString *)identifier completion:(void(^)(NSDictionary *firmware, NSError *error))completion {
    NSString *urlStr = [NSString stringWithFormat:@"https://api.ipsw.me/v4/device/%@?type=ipsw", identifier];
    NSURL *url = [NSURL URLWithString:urlStr];
    
    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithURL:url 
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            if (error) {
                completion(nil, error);
                return;
            }
            
            NSError *jsonError;
            NSDictionary *deviceInfo = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
            if (jsonError) {
                completion(nil, jsonError);
                return;
            }
            
            // Get latest signed firmware, or first firmware if none signed
            NSArray *firmwares = deviceInfo[@"firmwares"];
            NSDictionary *latestFirmware = nil;
            
            for (NSDictionary *fw in firmwares) {
                if ([fw[@"signed"] boolValue]) {
                    latestFirmware = fw;
                    break;
                }
            }
            
            // Fallback to first firmware if no signed found
            if (!latestFirmware && firmwares.count > 0) {
                latestFirmware = firmwares[0];
            }
            
            if (latestFirmware) {
                NSString *iosVersion = latestFirmware[@"version"];
                completion(@{
                    @"model": identifier,
                    @"name": deviceInfo[@"name"],
                    @"ios": iosVersion ?: @"18.0",
                    @"build": latestFirmware[@"buildid"] ?: @"22A3354",
                    @"darwin": [self darwinVersionForIOS:iosVersion]
                }, nil);
            } else {
                completion(nil, [NSError errorWithDomain:@"FakeInfo" code:404 userInfo:@{NSLocalizedDescriptionKey: @"No firmware found"}]);
            }
        }];
    [task resume];
}

// Update database from API (async, caches result)
- (void)updateDatabaseFromAPIWithCompletion:(void(^)(BOOL success, NSInteger count))completion {
    [self fetchDevicesFromAPI:^(NSArray *devices, NSError *error) {
        if (error || !devices || devices.count == 0) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, 0);
            });
            return;
        }
        
        // Randomly select 20 devices to fetch firmware (to avoid too many requests)
        NSMutableArray *shuffled = [devices mutableCopy];
        for (NSUInteger i = shuffled.count - 1; i > 0; i--) {
            NSUInteger j = arc4random_uniform((uint32_t)(i + 1));
            [shuffled exchangeObjectAtIndex:i withObjectAtIndex:j];
        }
        
        NSArray *selectedDevices = [shuffled subarrayWithRange:NSMakeRange(0, MIN(20, shuffled.count))];
        
        __block NSMutableArray *fullDevices = [NSMutableArray array];
        __block NSInteger completed = 0;
        
        for (NSDictionary *device in selectedDevices) {
            [self fetchFirmwareForDevice:device[@"model"] completion:^(NSDictionary *firmware, NSError *fwError) {
                if (firmware) {
                    @synchronized(fullDevices) {
                        [fullDevices addObject:firmware];
                    }
                }
                
                completed++;
                if (completed == selectedDevices.count) {
                    // All done, cache the results
                    if (fullDevices.count > 0) {
                        [self cacheDevices:fullDevices];
                    }
                    dispatch_async(dispatch_get_main_queue(), ^{
                        if (completion) completion(fullDevices.count > 0, fullDevices.count);
                    });
                }
            }];
        }
    }];
}

// Local fallback database (used when offline)
- (NSArray *)getLocalDeviceDatabase {
    return @[
        // iPhone 16 Series (2024) - iOS 18.x
        @{@"model": @"iPhone17,2", @"name": @"iPhone 16 Pro Max", @"ios": @"18.1.1", @"darwin": @"24.1.0", @"build": @"22B91"},
        @{@"model": @"iPhone17,1", @"name": @"iPhone 16 Pro", @"ios": @"18.1", @"darwin": @"24.1.0", @"build": @"22B83"},
        @{@"model": @"iPhone17,4", @"name": @"iPhone 16 Plus", @"ios": @"18.0.1", @"darwin": @"24.0.0", @"build": @"22A3370"},
        @{@"model": @"iPhone17,3", @"name": @"iPhone 16", @"ios": @"18.0", @"darwin": @"24.0.0", @"build": @"22A3354"},
        
        // iPhone 15 Series (2023) - iOS 17.x
        @{@"model": @"iPhone16,2", @"name": @"iPhone 15 Pro Max", @"ios": @"17.5.1", @"darwin": @"23.5.0", @"build": @"21F90"},
        @{@"model": @"iPhone16,1", @"name": @"iPhone 15 Pro", @"ios": @"17.4.1", @"darwin": @"23.4.0", @"build": @"21E237"},
        @{@"model": @"iPhone15,5", @"name": @"iPhone 15 Plus", @"ios": @"17.3.1", @"darwin": @"23.3.0", @"build": @"21D61"},
        @{@"model": @"iPhone15,4", @"name": @"iPhone 15", @"ios": @"17.2.1", @"darwin": @"23.2.0", @"build": @"21C66"},
        
        // iPhone 14 Series (2022) - iOS 16.x
        @{@"model": @"iPhone15,3", @"name": @"iPhone 14 Pro Max", @"ios": @"16.7.2", @"darwin": @"22.6.0", @"build": @"20H115"},
        @{@"model": @"iPhone15,2", @"name": @"iPhone 14 Pro", @"ios": @"16.6.1", @"darwin": @"22.6.0", @"build": @"20G81"},
        @{@"model": @"iPhone14,8", @"name": @"iPhone 14 Plus", @"ios": @"16.5.1", @"darwin": @"22.5.0", @"build": @"20F75"},
        @{@"model": @"iPhone14,7", @"name": @"iPhone 14", @"ios": @"16.4.1", @"darwin": @"22.4.0", @"build": @"20E252"},
        
        // iPhone 13 Series (2021)
        @{@"model": @"iPhone14,3", @"name": @"iPhone 13 Pro Max", @"ios": @"17.1.2", @"darwin": @"23.1.0", @"build": @"21B101"},
        @{@"model": @"iPhone14,2", @"name": @"iPhone 13 Pro", @"ios": @"16.3.1", @"darwin": @"22.3.0", @"build": @"20D67"},
        @{@"model": @"iPhone14,5", @"name": @"iPhone 13", @"ios": @"15.7.9", @"darwin": @"21.6.0", @"build": @"19H365"},
        @{@"model": @"iPhone14,4", @"name": @"iPhone 13 mini", @"ios": @"15.6.1", @"darwin": @"21.6.0", @"build": @"19G82"},
        
        // iPhone 12 Series (2020)
        @{@"model": @"iPhone13,4", @"name": @"iPhone 12 Pro Max", @"ios": @"16.2", @"darwin": @"22.2.0", @"build": @"20C65"},
        @{@"model": @"iPhone13,3", @"name": @"iPhone 12 Pro", @"ios": @"15.5", @"darwin": @"21.5.0", @"build": @"19F77"},
        @{@"model": @"iPhone13,2", @"name": @"iPhone 12", @"ios": @"15.4.1", @"darwin": @"21.4.0", @"build": @"19E258"},
        @{@"model": @"iPhone13,1", @"name": @"iPhone 12 mini", @"ios": @"15.3.1", @"darwin": @"21.3.0", @"build": @"19D52"},
        
        // iPhone 11 Series (2019)
        @{@"model": @"iPhone12,5", @"name": @"iPhone 11 Pro Max", @"ios": @"15.2.1", @"darwin": @"21.2.0", @"build": @"19C63"},
        @{@"model": @"iPhone12,3", @"name": @"iPhone 11 Pro", @"ios": @"15.1", @"darwin": @"21.1.0", @"build": @"19B74"},
        @{@"model": @"iPhone12,1", @"name": @"iPhone 11", @"ios": @"15.0.2", @"darwin": @"21.0.0", @"build": @"19A404"},
        
        // iPhone XS/XR/X/8 Series
        @{@"model": @"iPhone11,6", @"name": @"iPhone XS Max", @"ios": @"15.7.1", @"darwin": @"21.6.0", @"build": @"19H117"},
        @{@"model": @"iPhone11,2", @"name": @"iPhone XS", @"ios": @"14.7.1", @"darwin": @"20.5.0", @"build": @"18G82"},
        @{@"model": @"iPhone11,8", @"name": @"iPhone XR", @"ios": @"16.7.5", @"darwin": @"22.6.0", @"build": @"20H307"},
        @{@"model": @"iPhone10,6", @"name": @"iPhone X", @"ios": @"16.7.4", @"darwin": @"22.6.0", @"build": @"20H240"},
        @{@"model": @"iPhone10,5", @"name": @"iPhone 8 Plus", @"ios": @"16.7.3", @"darwin": @"22.6.0", @"build": @"20H232"},
        @{@"model": @"iPhone10,4", @"name": @"iPhone 8", @"ios": @"15.8", @"darwin": @"21.6.0", @"build": @"19H370"},
        
        // iPhone SE Series
        @{@"model": @"iPhone14,6", @"name": @"iPhone SE 3rd Gen", @"ios": @"17.3", @"darwin": @"23.3.0", @"build": @"21D50"},
        @{@"model": @"iPhone12,8", @"name": @"iPhone SE 2nd Gen", @"ios": @"16.6", @"darwin": @"22.5.0", @"build": @"20G75"},
    ];
}

// Get devices (from cache or local fallback)
- (NSArray *)getDeviceDatabase {
    // Try cached devices first
    if ([self isCacheValid]) {
        NSArray *cached = [self getCachedDevices];
        if (cached && cached.count > 0) {
            SafeLog(@"📱 Using %lu cached devices from API", (unsigned long)cached.count);
            return cached;
        }
    }
    
    // Fallback to local database
    SafeLog(@"📱 Using local device database (offline mode)");
    return [self getLocalDeviceDatabase];
}

- (void)randomAllSettings {
    // Get device database (cached API data or local fallback)
    NSArray *realDevices = [self getDeviceDatabase];
    
    // Try to update cache in background if expired (non-blocking)
    if (![self isCacheValid]) {
        [self updateDatabaseFromAPIWithCompletion:^(BOOL success, NSInteger count) {
            if (success) {
                SafeLog(@"🔄 Background cache update: %ld devices", (long)count);
            }
        }];
    }
    
    // Pick random device
    NSDictionary *device = realDevices[arc4random_uniform((uint32_t)realDevices.count)];
    
    // Generate random UUIDs
    NSString *vendorUUID = [self generateRandomUUID];
    NSString *idfaUUID = [self generateRandomUUID];
    
    // Real WiFi IP ranges
    NSArray *realIPPrefixes = @[
        @"192.168.1", @"192.168.0", @"192.168.2", @"192.168.10", @"192.168.100",
        @"10.0.0", @"10.0.1", @"10.1.1", @"172.16.0", @"172.16.1"
    ];
    NSString *ipPrefix = realIPPrefixes[arc4random_uniform((uint32_t)realIPPrefixes.count)];
    NSString *ip = [NSString stringWithFormat:@"%@.%d", ipPrefix, arc4random_uniform(200) + 2];
    
    // Real device names
    NSArray *deviceNames = @[
        [NSString stringWithFormat:@"%@", device[@"name"]],
        [NSString stringWithFormat:@"%@ của tôi", device[@"name"]],
        @"iPhone", @"iPhone của tôi", @"My iPhone",
        @"Phone", @"Personal", @"Main Phone", @"Work iPhone"
    ];
    NSString *deviceName = deviceNames[arc4random_uniform((uint32_t)deviceNames.count)];
    
    // ============================================================================
    // NEW: Deep Identity Faking - Locale, Timezone, Carrier
    // ============================================================================
    
    // Locale + Timezone combinations (realistic pairings)
    NSArray *localeData = @[
        @{@"locale": @"en_US", @"timezone": @"America/New_York", @"carrier": @"AT&T"},
        @{@"locale": @"en_US", @"timezone": @"America/Los_Angeles", @"carrier": @"Verizon"},
        @{@"locale": @"en_US", @"timezone": @"America/Chicago", @"carrier": @"T-Mobile"},
        @{@"locale": @"en_GB", @"timezone": @"Europe/London", @"carrier": @"EE"},
        @{@"locale": @"en_AU", @"timezone": @"Australia/Sydney", @"carrier": @"Telstra"},
        @{@"locale": @"vi_VN", @"timezone": @"Asia/Ho_Chi_Minh", @"carrier": @"Viettel"},
        @{@"locale": @"vi_VN", @"timezone": @"Asia/Ho_Chi_Minh", @"carrier": @"Mobifone"},
        @{@"locale": @"vi_VN", @"timezone": @"Asia/Ho_Chi_Minh", @"carrier": @"Vinaphone"},
        @{@"locale": @"ja_JP", @"timezone": @"Asia/Tokyo", @"carrier": @"NTT DOCOMO"},
        @{@"locale": @"ja_JP", @"timezone": @"Asia/Tokyo", @"carrier": @"SoftBank"},
        @{@"locale": @"ko_KR", @"timezone": @"Asia/Seoul", @"carrier": @"SK Telecom"},
        @{@"locale": @"zh_CN", @"timezone": @"Asia/Shanghai", @"carrier": @"China Mobile"},
        @{@"locale": @"zh_TW", @"timezone": @"Asia/Taipei", @"carrier": @"Chunghwa Telecom"},
        @{@"locale": @"de_DE", @"timezone": @"Europe/Berlin", @"carrier": @"Deutsche Telekom"},
        @{@"locale": @"fr_FR", @"timezone": @"Europe/Paris", @"carrier": @"Orange"},
        @{@"locale": @"es_ES", @"timezone": @"Europe/Madrid", @"carrier": @"Movistar"},
        @{@"locale": @"pt_BR", @"timezone": @"America/Sao_Paulo", @"carrier": @"Vivo"},
        @{@"locale": @"ru_RU", @"timezone": @"Europe/Moscow", @"carrier": @"MTS"},
        @{@"locale": @"in_ID", @"timezone": @"Asia/Jakarta", @"carrier": @"Telkomsel"},
        @{@"locale": @"th_TH", @"timezone": @"Asia/Bangkok", @"carrier": @"AIS"},
    ];
    NSDictionary *randomLocale = localeData[arc4random_uniform((uint32_t)localeData.count)];
    
    // Boot time: random between 1 hour and 7 days ago (fresh device feel)
    NSTimeInterval bootOffset = (arc4random_uniform(7 * 24 * 60) + 60) * 60; // 1h to 7d in seconds
    NSDate *fakeBootTime = [NSDate dateWithTimeIntervalSinceNow:-bootOffset];
    NSString *bootTimeStr = [NSString stringWithFormat:@"%.0f", [fakeBootTime timeIntervalSince1970]];
    
    // Apply all settings
    FakeSettings *settings = [FakeSettings shared];
    
    // Device info
    settings.settings[@"systemVersion"] = device[@"ios"];
    settings.settings[@"deviceModel"] = device[@"model"];
    settings.settings[@"deviceName"] = deviceName;
    settings.settings[@"identifierForVendor"] = vendorUUID;
    settings.settings[@"bundleVersion"] = device[@"build"];
    settings.settings[@"darwinVersion"] = device[@"darwin"];
    settings.settings[@"wifiIP"] = ip;
    
    // NEW: Deep identity
    settings.settings[@"idfa"] = idfaUUID;
    settings.settings[@"locale"] = randomLocale[@"locale"];
    settings.settings[@"timezone"] = randomLocale[@"timezone"];
    settings.settings[@"carrier"] = randomLocale[@"carrier"];
    settings.settings[@"bootTime"] = bootTimeStr;
    
    // Enable all toggles
    settings.toggles[@"systemVersion"] = @YES;
    settings.toggles[@"deviceModel"] = @YES;
    settings.toggles[@"deviceName"] = @YES;
    settings.toggles[@"identifierForVendor"] = @YES;
    settings.toggles[@"bundleVersion"] = @YES;
    settings.toggles[@"darwinVersion"] = @YES;
    settings.toggles[@"wifiIP"] = @YES;
    settings.toggles[@"idfa"] = @YES;
    settings.toggles[@"locale"] = @YES;
    settings.toggles[@"timezone"] = @YES;
    settings.toggles[@"carrier"] = @YES;
    settings.toggles[@"bootTime"] = @YES;
    settings.toggles[@"keychain"] = @YES;
    settings.toggles[@"jailbreak"] = @YES;
    
    SafeLog(@"🎲 Deep Random Applied: %@ (%@) iOS %@ | %@ | %@ | %@", 
            device[@"name"], device[@"model"], device[@"ios"],
            randomLocale[@"locale"], randomLocale[@"timezone"], randomLocale[@"carrier"]);
}

- (NSString *)generateRandomUUID {
    // Generate a valid UUID v4 format
    return [[NSUUID UUID] UUIDString];
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
    SafeLog(@"🔧 ShowSettingsUI called");
    
    // Close existing window if any
    if (settingsWindow) {
        SafeLog(@"🔧 Closing existing settings window");
        settingsWindow.hidden = YES;
        settingsWindow = nil;
        hasShownSettings = NO;
        return; // Toggle behavior - if was open, just close
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            SafeLog(@"🔧 Creating new settings window...");
            
            // For iOS 13+, we need to use UIWindowScene
            if (@available(iOS 13.0, *)) {
                UIWindowScene *windowScene = nil;
                for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
                    if (scene.activationState == UISceneActivationStateForegroundActive) {
                        windowScene = scene;
                        break;
                    }
                }
                
                if (windowScene) {
                    settingsWindow = [[UIWindow alloc] initWithWindowScene:windowScene];
                    SafeLog(@"🔧 Created window with windowScene");
                } else {
                    settingsWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
                    SafeLog(@"🔧 Created window with frame (no scene found)");
                }
            } else {
                settingsWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
                SafeLog(@"🔧 Created window with frame (iOS < 13)");
            }
            
            if (!settingsWindow) {
                SafeLog(@"❌ Failed to create settings window!");
                return;
            }
            
            settingsWindow.frame = [UIScreen mainScreen].bounds;
            settingsWindow.windowLevel = UIWindowLevelAlert + 100;
            settingsWindow.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.9];
            
            FakeSettingsViewController *settingsVC = [[FakeSettingsViewController alloc] init];
            if (!settingsVC) {
                SafeLog(@"❌ Failed to create FakeSettingsViewController!");
                return;
            }
            
            settingsWindow.rootViewController = settingsVC;
            settingsWindow.hidden = NO;
            [settingsWindow makeKeyAndVisible];
            hasShownSettings = YES;
            
            SafeLog(@"✅ Settings UI presented successfully! Frame: %@", NSStringFromCGRect(settingsWindow.frame));
        } @catch (NSException *e) {
            SafeLog(@"❌ Exception in ShowSettingsUI: %@", e.reason);
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
        // NEW: Fake boot time to simulate fresh device
        if ([settings isEnabled:@"bootTime"] && strcmp(name, "kern.boottime") == 0) {
            NSString *bootTimeStr = [settings valueForKey:@"bootTime"];
            if (bootTimeStr && oldp && oldlenp && *oldlenp >= sizeof(struct timeval)) {
                struct timeval *tv = (struct timeval *)oldp;
                tv->tv_sec = (time_t)[bootTimeStr longLongValue];
                tv->tv_usec = 0;
                SafeLog(@"⏰ Faking boot time: %@", bootTimeStr);
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

// ============================================================================
// MARK: - Deep Identity Faking Hooks
// ============================================================================

// MARK: - Fake IDFA (Advertising Identifier)
%hook ASIdentifierManager
- (NSUUID *)advertisingIdentifier {
    @try {
        FakeSettings *settings = [FakeSettings shared];
        if ([settings isEnabled:@"idfa"]) {
            NSString *fakeIDFA = [settings valueForKey:@"idfa"];
            if (fakeIDFA && fakeIDFA.length > 0) {
                NSUUID *uuid = [[NSUUID alloc] initWithUUIDString:fakeIDFA];
                if (uuid) {
                    SafeLog(@"📺 Faking IDFA: %@", fakeIDFA);
                    return uuid;
                }
            }
        }
    } @catch(NSException *e) { SafeLog(@"[CRASH] ASIdentifierManager.advertisingIdentifier: %@", e.reason); }
    return %orig;
}

- (BOOL)isAdvertisingTrackingEnabled {
    @try {
        FakeSettings *settings = [FakeSettings shared];
        if ([settings isEnabled:@"idfa"]) {
            SafeLog(@"📺 Faking ad tracking: disabled");
            return NO; // Simulate user disabled ad tracking
        }
    } @catch(NSException *e) { SafeLog(@"[CRASH] ASIdentifierManager.isAdvertisingTrackingEnabled: %@", e.reason); }
    return %orig;
}
%end

// MARK: - Fake Locale/Language
%hook NSLocale
+ (NSLocale *)currentLocale {
    @try {
        FakeSettings *settings = [FakeSettings shared];
        if ([settings isEnabled:@"locale"]) {
            NSString *fakeLocale = [settings valueForKey:@"locale"];
            if (fakeLocale && fakeLocale.length > 0) {
                SafeLog(@"🌍 Faking locale: %@", fakeLocale);
                return [[NSLocale alloc] initWithLocaleIdentifier:fakeLocale];
            }
        }
    } @catch(NSException *e) { SafeLog(@"[CRASH] NSLocale.currentLocale: %@", e.reason); }
    return %orig;
}

+ (NSLocale *)autoupdatingCurrentLocale {
    @try {
        FakeSettings *settings = [FakeSettings shared];
        if ([settings isEnabled:@"locale"]) {
            NSString *fakeLocale = [settings valueForKey:@"locale"];
            if (fakeLocale && fakeLocale.length > 0) {
                return [[NSLocale alloc] initWithLocaleIdentifier:fakeLocale];
            }
        }
    } @catch(NSException *e) { SafeLog(@"[CRASH] NSLocale.autoupdatingCurrentLocale: %@", e.reason); }
    return %orig;
}

+ (NSArray *)preferredLanguages {
    @try {
        FakeSettings *settings = [FakeSettings shared];
        if ([settings isEnabled:@"locale"]) {
            NSString *fakeLocale = [settings valueForKey:@"locale"];
            if (fakeLocale && fakeLocale.length > 0) {
                // Extract language code from locale (e.g., "en" from "en_US")
                NSString *langCode = [[fakeLocale componentsSeparatedByString:@"_"] firstObject];
                return @[langCode, fakeLocale];
            }
        }
    } @catch(NSException *e) { SafeLog(@"[CRASH] NSLocale.preferredLanguages: %@", e.reason); }
    return %orig;
}
%end

// MARK: - Fake Timezone
%hook NSTimeZone
+ (NSTimeZone *)localTimeZone {
    @try {
        FakeSettings *settings = [FakeSettings shared];
        if ([settings isEnabled:@"timezone"]) {
            NSString *fakeTZ = [settings valueForKey:@"timezone"];
            if (fakeTZ && fakeTZ.length > 0) {
                NSTimeZone *tz = [NSTimeZone timeZoneWithName:fakeTZ];
                if (tz) {
                    SafeLog(@"🕐 Faking timezone: %@", fakeTZ);
                    return tz;
                }
            }
        }
    } @catch(NSException *e) { SafeLog(@"[CRASH] NSTimeZone.localTimeZone: %@", e.reason); }
    return %orig;
}

+ (NSTimeZone *)systemTimeZone {
    @try {
        FakeSettings *settings = [FakeSettings shared];
        if ([settings isEnabled:@"timezone"]) {
            NSString *fakeTZ = [settings valueForKey:@"timezone"];
            if (fakeTZ && fakeTZ.length > 0) {
                NSTimeZone *tz = [NSTimeZone timeZoneWithName:fakeTZ];
                if (tz) return tz;
            }
        }
    } @catch(NSException *e) { SafeLog(@"[CRASH] NSTimeZone.systemTimeZone: %@", e.reason); }
    return %orig;
}

+ (NSTimeZone *)defaultTimeZone {
    @try {
        FakeSettings *settings = [FakeSettings shared];
        if ([settings isEnabled:@"timezone"]) {
            NSString *fakeTZ = [settings valueForKey:@"timezone"];
            if (fakeTZ && fakeTZ.length > 0) {
                NSTimeZone *tz = [NSTimeZone timeZoneWithName:fakeTZ];
                if (tz) return tz;
            }
        }
    } @catch(NSException *e) { SafeLog(@"[CRASH] NSTimeZone.defaultTimeZone: %@", e.reason); }
    return %orig;
}
%end

// MARK: - Fake Carrier
%hook CTCarrier
- (NSString *)carrierName {
    @try {
        FakeSettings *settings = [FakeSettings shared];
        if ([settings isEnabled:@"carrier"]) {
            NSString *fakeCarrier = [settings valueForKey:@"carrier"];
            if (fakeCarrier && fakeCarrier.length > 0) {
                SafeLog(@"📶 Faking carrier: %@", fakeCarrier);
                return fakeCarrier;
            }
        }
    } @catch(NSException *e) { SafeLog(@"[CRASH] CTCarrier.carrierName: %@", e.reason); }
    return %orig;
}

- (NSString *)isoCountryCode {
    @try {
        FakeSettings *settings = [FakeSettings shared];
        if ([settings isEnabled:@"locale"]) {
            NSString *fakeLocale = [settings valueForKey:@"locale"];
            if (fakeLocale && fakeLocale.length > 0) {
                // Extract country code from locale (e.g., "US" from "en_US")
                NSArray *parts = [fakeLocale componentsSeparatedByString:@"_"];
                if (parts.count > 1) {
                    return [parts[1] lowercaseString];
                }
            }
        }
    } @catch(NSException *e) { SafeLog(@"[CRASH] CTCarrier.isoCountryCode: %@", e.reason); }
    return %orig;
}
%end

// MARK: - Fake CTTelephonyNetworkInfo
%hook CTTelephonyNetworkInfo
- (CTCarrier *)subscriberCellularProvider {
    // Return orig but carrier name will be hooked above
    return %orig;
}
%end

// MARK: - Fake Keychain (to make app think device is fresh/new)
OSStatus fake_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    @try {
        FakeSettings *settings = [FakeSettings shared];
        if ([settings isEnabled:@"keychain"]) {
            SafeLog(@"🔐 SecItemCopyMatching blocked - returning errSecItemNotFound");
            if (result) *result = NULL;
            return errSecItemNotFound; // -25300: Item not found
        }
    } @catch(NSException *e) { SafeLog(@"[CRASH] SecItemCopyMatching: %@", e.reason); }
    
    if (orig_SecItemCopyMatching_ptr) {
        return orig_SecItemCopyMatching_ptr(query, result);
    }
    return errSecItemNotFound;
}

OSStatus fake_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    @try {
        FakeSettings *settings = [FakeSettings shared];
        if ([settings isEnabled:@"keychain"]) {
            SafeLog(@"🔐 SecItemAdd blocked - faking success without storing");
            if (result) *result = NULL;
            return errSecSuccess; // Fake success but don't actually store
        }
    } @catch(NSException *e) { SafeLog(@"[CRASH] SecItemAdd: %@", e.reason); }
    
    if (orig_SecItemAdd_ptr) {
        return orig_SecItemAdd_ptr(attributes, result);
    }
    return errSecSuccess;
}

OSStatus fake_SecItemDelete(CFDictionaryRef query) {
    @try {
        FakeSettings *settings = [FakeSettings shared];
        if ([settings isEnabled:@"keychain"]) {
            SafeLog(@"🔐 SecItemDelete - returning success");
            return errSecSuccess;
        }
    } @catch(NSException *e) { SafeLog(@"[CRASH] SecItemDelete: %@", e.reason); }
    
    if (orig_SecItemDelete_ptr) {
        return orig_SecItemDelete_ptr(query);
    }
    return errSecSuccess;
}

// MARK: - Shake to Open Settings (Alternative to 4-finger gesture)
%hook UIApplication
- (void)sendEvent:(UIEvent *)event {
    %orig;
    
    if (event.type == UIEventTypeMotion && event.subtype == UIEventSubtypeMotionShake) {
        static NSTimeInterval lastShakeTime = 0;
        NSTimeInterval currentTime = [[NSDate date] timeIntervalSince1970];
        
        // Debounce: only trigger once every 2 seconds
        if (currentTime - lastShakeTime > 2.0) {
            lastShakeTime = currentTime;
            SafeLog(@"📳 Shake detected! Opening Settings UI...");
            
            dispatch_async(dispatch_get_main_queue(), ^{
                ShowSettingsUI();
                
                // Haptic feedback
                if (@available(iOS 10.0, *)) {
                    UIImpactFeedbackGenerator *feedback = [[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleMedium];
                    [feedback impactOccurred];
                }
            });
        }
    }
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

            // Keychain hooks for fresh device simulation
            void *ptr_SecItemCopyMatching = dlsym(handle, "SecItemCopyMatching");
            void *ptr_SecItemAdd = dlsym(handle, "SecItemAdd");
            void *ptr_SecItemDelete = dlsym(handle, "SecItemDelete");
            
            if (ptr_SecItemCopyMatching) MSHookFunction(ptr_SecItemCopyMatching, (void *)&fake_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching_ptr);
            if (ptr_SecItemAdd) MSHookFunction(ptr_SecItemAdd, (void *)&fake_SecItemAdd, (void **)&orig_SecItemAdd_ptr);
            if (ptr_SecItemDelete) MSHookFunction(ptr_SecItemDelete, (void *)&fake_SecItemDelete, (void **)&orig_SecItemDelete_ptr);
            
            SafeLog(@"🔐 Keychain hooks installed");

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

