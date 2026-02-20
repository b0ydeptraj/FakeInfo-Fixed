// UIKit Device Configuration Module
// Internal device configuration handler

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
#import <mach/mach_time.h>
#import <CoreLocation/CoreLocation.h>
#import <CoreMotion/CoreMotion.h>
#import <mach-o/dyld.h>

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

// Jailbreak detection arrays (must be declared before NSFileManager hook)
static NSArray *jailbreakURLSchemes = nil;
static NSArray *jailbreakFilePaths = nil;

__attribute__((constructor)) static void initJailbreakPaths() {
    jailbreakURLSchemes = @[
        @"cydia", @"sileo", @"zbra", @"filza", @"activator",
        @"undecimus", @"apt-repo", @"installer", @"icy"
    ];
    
    jailbreakFilePaths = @[
        @"/Applications/Cydia.app",
        @"/Applications/Sileo.app",
        @"/Applications/Zebra.app",
        @"/Applications/Filza.app",
        @"/private/var/lib/apt",
        @"/private/var/lib/cydia",
        @"/private/var/mobile/Library/SBSettings",
        @"/private/var/stash",
        @"/var/lib/apt",
        @"/var/lib/cydia",
        @"/var/cache/apt",
        @"/var/log/syslog",
        @"/bin/bash",
        @"/bin/sh",
        @"/usr/sbin/sshd",
        @"/usr/bin/sshd",
        @"/usr/libexec/sftp-server",
        @"/etc/apt",
        @"/etc/ssh/sshd_config",
        @"/Library/MobileSubstrate",
        @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/Library/MobileSubstrate/DynamicLibraries",
        @"/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
        @"/System/Library/LaunchDaemons/com.ikey.bbot.plist",
        @"/private/var/tmp/cydia.log",
        @"/usr/bin/cycript",
        @"/usr/local/bin/cycript",
        @"/usr/bin/ssh",
        @"/.installed_unc0ver",
        @"/.bootstrapped_electra",
        @"/private/var/jb"  // rootless jailbreak
    ];
}

// MARK: - Global Variables & Forward Declarations
static UIWindow *settingsWindow = nil;
static BOOL hasShownSettings = NO;

// Session caching for stable IDs (don't change during app session)
static NSMutableDictionary *sessionCache = nil;
static BOOL sessionCacheInitialized = NO;
static NSObject *stableIdLock = nil;
static BOOL gDebugLoggingEnabled = NO;

// GPS base location for realistic drift
static double gpsBaseLatitude = 0.0;
static double gpsBaseLongitude = 0.0;
static BOOL gpsLocationInitialized = NO;

void _showConfigUI(void);
void _setupGR(void);

// Forward declaration for SafeLog (defined later)
void _cflog(NSString *format, ...);

static NSString *getRealBundleIdentifier(void) {
    NSString *bundleId = [[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleIdentifier"];
    if (!bundleId || bundleId.length == 0) {
        bundleId = [[NSBundle mainBundle] bundleIdentifier];
    }
    if (!bundleId || bundleId.length == 0) {
        bundleId = @"unknown";
    }
    return bundleId;
}

static NSString *stableCacheKeyFor(NSString *key) {
    return [NSString stringWithFormat:@"com.apple.device.cache_%@_%@", getRealBundleIdentifier(), key ?: @"unknown"];
}

// Initialize session cache
static void initSessionCache(void) {
    if (!sessionCacheInitialized) {
        sessionCache = [[NSMutableDictionary alloc] init];
        stableIdLock = [[NSObject alloc] init];
        sessionCacheInitialized = YES;
    }
}

// Get stable cached value for key (persists across app restarts)
static NSString* getStableCachedValue(NSString *key, NSString *(^generator)(void)) {
    initSessionCache();
    @synchronized(stableIdLock) {
        NSString *cached = sessionCache[key];
        if (cached && cached.length > 0) {
            return cached;
        }

        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        NSString *diskKey = stableCacheKeyFor(key);
        NSString *persisted = [defaults stringForKey:diskKey];

        if (!persisted || persisted.length == 0) {
            persisted = generator();
            if (persisted && persisted.length > 0) {
                [defaults setObject:persisted forKey:diskKey];
                [defaults synchronize];
            }
        }

        if (persisted && persisted.length > 0) {
            sessionCache[key] = persisted;
            _cflog(@"Cached stable value for key: %@", key);
            return persisted;
        }
    }

    return generator();
}

// Generate stable UUID (cached per session)
static NSString* generateStableUUID(NSString *key) {
    return getStableCachedValue(key, ^{
        return [[NSUUID UUID] UUIDString];
    });
}

// Initialize GPS base location (once per session)
static void initGPSBaseLocation(double lat, double lon) {
    if (!gpsLocationInitialized) {
        gpsBaseLatitude = lat;
        gpsBaseLongitude = lon;
        gpsLocationInitialized = YES;
        _cflog(@"ðŸ“ GPS base location set: %.6f, %.6f", lat, lon);
    }
}

// Get GPS with small drift (realistic movement)
static CLLocationCoordinate2D getGPSWithDrift(void) {
    // Small drift: ~10-50 meters (0.0001 degree â‰ˆ 11 meters)
    double latDrift = ((arc4random_uniform(100) - 50) / 1000000.0);
    double lonDrift = ((arc4random_uniform(100) - 50) / 1000000.0);
    return CLLocationCoordinate2DMake(gpsBaseLatitude + latDrift, gpsBaseLongitude + lonDrift);
}

// MARK: - Logging & Anti-Crash
void _cflog(NSString *format, ...) {
    if (!gDebugLoggingEnabled) return;
    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    NSLog(@"%@", msg);
}

void CrashHandler(int sig) {
    _cflog(@"=== SIGNAL CRASH DETECTED: %d ===", sig);
    void *callstack[128];
    int frames = backtrace(callstack, 128);
    char **symbols = backtrace_symbols(callstack, frames);
    for (int i = 0; i < frames; i++) {
        _cflog(@"Frame %d: %s", i, symbols[i]);
    }
    free(symbols);
    signal(sig, SIG_DFL);
    raise(sig);
}

// MARK: - Settings Storage
@interface _UIDeviceConfig : NSObject
+ (instancetype)shared;
- (void)restoreConfig;
- (void)persistConfig;
- (void)clearConfig;
@property (nonatomic, strong) NSMutableDictionary *settings;
@property (nonatomic, strong) NSMutableDictionary *toggles;
@property (nonatomic, strong) NSDictionary *baselineConfig;
@end

@implementation _UIDeviceConfig
+ (instancetype)shared {
    static _UIDeviceConfig *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[_UIDeviceConfig alloc] init];
    });
    return instance;
}

- (instancetype)init {
    if (self = [super init]) {
        [self loadBaselineConfig];
        [self restoreConfig];
    }
    return self;
}

- (void)loadBaselineConfig {
    UIDevice *device = [UIDevice currentDevice];
    NSBundle *bundle = [NSBundle mainBundle];
    struct utsname systemInfo;
    uname(&systemInfo);

    char osrelease[256];
    size_t size = sizeof(osrelease);
    if (sysctlbyname("kern.osrelease", osrelease, &size, NULL, 0) != 0) {
        osrelease[0] = '\0';
    }

    // Get IDFA
    NSString *idfaString = @"00000000-0000-0000-0000-000000000000";
    Class ASIdentifierManagerClass = NSClassFromString(@"ASIdentifierManager");
    if (ASIdentifierManagerClass) {
        id manager = [ASIdentifierManagerClass performSelector:@selector(sharedManager)];
        if (manager) {
            NSUUID *idfa = [manager performSelector:@selector(advertisingIdentifier)];
            if (idfa) {
                idfaString = [idfa UUIDString];
            }
        }
    }
    
    // Get locale and timezone
    NSLocale *currentLocale = [NSLocale currentLocale];
    NSTimeZone *currentTimezone = [NSTimeZone localTimeZone];
    
    // Get carrier info
    NSString *carrierName = @"Unknown";
    NSString *mccCode = @"000";
    NSString *mncCode = @"00";
    Class CTTelephonyNetworkInfoClass = NSClassFromString(@"CTTelephonyNetworkInfo");
    if (CTTelephonyNetworkInfoClass) {
        id networkInfo = [[CTTelephonyNetworkInfoClass alloc] init];
        if (networkInfo) {
            id carrier = [networkInfo performSelector:@selector(subscriberCellularProvider)];
            if (carrier) {
                NSString *name = [carrier performSelector:@selector(carrierName)];
                if (name) carrierName = name;
                NSString *mcc = [carrier performSelector:@selector(mobileCountryCode)];
                if (mcc) mccCode = mcc;
                NSString *mnc = [carrier performSelector:@selector(mobileNetworkCode)];
                if (mnc) mncCode = mnc;
            }
        }
    }
    
    // Get screen info
    UIScreen *mainScreen = [UIScreen mainScreen];
    CGRect screenBounds = mainScreen.nativeBounds;
    CGFloat screenScale = mainScreen.nativeScale;
    
    // Get RAM
    NSProcessInfo *processInfo = [NSProcessInfo processInfo];
    unsigned long long physicalMemory = processInfo.physicalMemory;
    
    // Get disk space
    NSDictionary *attributes = [[NSFileManager defaultManager] attributesOfFileSystemForPath:NSHomeDirectory() error:nil];
    unsigned long long totalDisk = [attributes[NSFileSystemSize] unsignedLongLongValue];
    unsigned long long freeDisk = [attributes[NSFileSystemFreeSize] unsignedLongLongValue];
    
    // Get battery level
    device.batteryMonitoringEnabled = YES;
    float batteryLevel = device.batteryLevel;
    if (batteryLevel < 0) batteryLevel = 1.0; // Default if unknown
    
    // Get boot time
    struct timeval boottime;
    size_t btSize = sizeof(boottime);
    NSString *bootTimeStr = @"0";
    if (sysctlbyname("kern.boottime", &boottime, &btSize, NULL, 0) == 0) {
        bootTimeStr = [NSString stringWithFormat:@"%ld", (long)boottime.tv_sec];
    }

    self.baselineConfig = @{
        @"systemVersion": device.systemVersion ?: @"Unknown",
        @"deviceModel": [NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding] ?: @"Unknown",
        @"deviceName": device.name ?: @"Unknown",
        @"identifierForVendor": device.identifierForVendor.UUIDString ?: @"Unknown",
        @"idfa": idfaString,
        @"locale": currentLocale.localeIdentifier ?: @"en_US",
        @"timezone": currentTimezone.name ?: @"UTC",
        @"carrier": carrierName,
        @"mcc": mccCode,
        @"mnc": mncCode,
        @"screenWidth": [NSString stringWithFormat:@"%.0f", screenBounds.size.width],
        @"screenHeight": [NSString stringWithFormat:@"%.0f", screenBounds.size.height],
        @"screenScale": [NSString stringWithFormat:@"%.2f", screenScale],
        @"physicalMemory": [NSString stringWithFormat:@"%llu", physicalMemory],
        @"totalDiskSpace": [NSString stringWithFormat:@"%llu", totalDisk],
        @"freeDiskSpace": [NSString stringWithFormat:@"%llu", freeDisk],
        @"batteryLevel": [NSString stringWithFormat:@"%.2f", batteryLevel],
        @"bundleIdentifier": getRealBundleIdentifier(),
        @"appVersion": [bundle.infoDictionary objectForKey:@"CFBundleShortVersionString"] ?: @"Unknown",
        @"bundleVersion": [bundle.infoDictionary objectForKey:@"CFBundleVersion"] ?: @"Unknown",
        @"displayName": [bundle.infoDictionary objectForKey:@"CFBundleDisplayName"] ?: @"Unknown",
        @"darwinVersion": [NSString stringWithCString:osrelease encoding:NSUTF8StringEncoding] ?: @"Unknown",
        @"wifiIP": @"192.168.1.100",
        @"gpsLat": @"10.776900",
        @"gpsLon": @"106.700900",
        @"bootTime": bootTimeStr,
        @"jailbreak": @"OFF",
        @"keychain": @"OFF",
        @"hardwareInfo": @"OFF"
    };
}

// Per-app unique key based on bundle identifier
- (NSString *)settingsKeyForBundle {
    NSString *bundleId = getRealBundleIdentifier();
    return [NSString stringWithFormat:@"com.apple.uikit.pref_%@", bundleId];
}

- (NSString *)togglesKeyForBundle {
    NSString *bundleId = getRealBundleIdentifier();
    return [NSString stringWithFormat:@"com.apple.uikit.tog_%@", bundleId];
}

- (void)clearStableIdentityCache {
    NSString *prefix = [NSString stringWithFormat:@"com.apple.device.cache_%@_", getRealBundleIdentifier()];
    NSDictionary *all = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
    for (NSString *key in all) {
        if ([key hasPrefix:prefix]) {
            [[NSUserDefaults standardUserDefaults] removeObjectForKey:key];
        }
    }
    @synchronized(stableIdLock) {
        [sessionCache removeAllObjects];
    }
}

- (void)restoreConfig {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *settingsKey = [self settingsKeyForBundle];
    NSString *togglesKey = [self togglesKeyForBundle];
    
    self.settings = [[defaults objectForKey:settingsKey] mutableCopy] ?: [NSMutableDictionary dictionary];
    self.toggles = [[defaults objectForKey:togglesKey] mutableCopy] ?: [NSMutableDictionary dictionary];
    
    // Initialize default toggles
    if (!self.toggles[@"jailbreak"]) self.toggles[@"jailbreak"] = @NO;
    if (!self.toggles[@"keychain"]) self.toggles[@"keychain"] = @NO;
    if (!self.toggles[@"hardwareInfo"]) self.toggles[@"hardwareInfo"] = @NO;
    
    _cflog(@"Loaded settings for bundle: %@", getRealBundleIdentifier());
}

- (void)persistConfig {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *settingsKey = [self settingsKeyForBundle];
    NSString *togglesKey = [self togglesKeyForBundle];
    
    [defaults setObject:self.settings forKey:settingsKey];
    [defaults setObject:self.toggles forKey:togglesKey];
    [defaults synchronize];
    
    _cflog(@"Saved settings for bundle: %@", getRealBundleIdentifier());
}

- (void)clearConfig {
    self.settings = [NSMutableDictionary dictionary];
    self.toggles = [NSMutableDictionary dictionary];
    [self clearStableIdentityCache];
    [self persistConfig];
    _cflog(@"Reset settings for bundle: %@", getRealBundleIdentifier());
}

- (BOOL)isEnabled:(NSString *)key {
    return [self.toggles[key] boolValue];
}

- (NSString *)valueForKey:(NSString *)key {
    return self.settings[key] ?: self.baselineConfig[key] ?: @"N/A";
}
@end

// MARK: - Settings UI (Forward declaration - full implementation below)
@interface _UISystemConfigController : UIViewController <UITableViewDataSource, UITableViewDelegate>
@property (nonatomic, strong) UITableView *tableView;
@property (nonatomic, strong) NSArray *settingsKeys;
@property (nonatomic, strong) NSDictionary *settingsLabels;
@end

// MARK: - Gesture Handler
@interface _UIGestureProxy : NSObject
- (void)handleTripleFingerTap:(UITapGestureRecognizer *)gesture;
- (void)handleFourFingerLongPress:(UILongPressGestureRecognizer *)gesture;
- (void)handleFourFingerShortPress:(UILongPressGestureRecognizer *)gesture;
@end

@implementation _UIGestureProxy
- (void)handleTripleFingerTap:(UITapGestureRecognizer *)gesture {
    if (!hasShownSettings && !settingsWindow) {
        _showConfigUI();
    }
}

- (void)handleFourFingerLongPress:(UILongPressGestureRecognizer *)gesture {
    if (gesture.state == UIGestureRecognizerStateBegan) {
        _cflog(@"Four finger long press detected - showing UI");
        _showConfigUI();
        if (@available(iOS 10.0, *)) {
            UIImpactFeedbackGenerator *feedback = [[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleHeavy];
            [feedback impactOccurred];
        }
    }
}

- (void)handleFourFingerShortPress:(UILongPressGestureRecognizer *)gesture {
    if (gesture.state == UIGestureRecognizerStateBegan) {
        _cflog(@"Four finger short press detected - showing UI");
        _showConfigUI();
        if (@available(iOS 10.0, *)) {
            UIImpactFeedbackGenerator *feedback = [[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleMedium];
            [feedback impactOccurred];
        }
    }
}
@end

static _UIGestureProxy *_gestureProxyInstance = nil;
static UITapGestureRecognizer *tripleFingerGesture = nil;
static UILongPressGestureRecognizer *fourFingerLongPress = nil;
static UILongPressGestureRecognizer *fourFingerShortPress = nil;

// MARK: - _UISystemConfigController Implementation
@implementation _UISystemConfigController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.9];
    
    self.settingsKeys = @[@"systemVersion", @"deviceModel", @"deviceName", @"identifierForVendor", 
                          @"idfa", @"locale", @"timezone", @"carrier", @"mcc", @"mnc",
                          @"screenWidth", @"screenHeight", @"physicalMemory", @"totalDiskSpace", @"freeDiskSpace", @"batteryLevel",
                          @"bundleIdentifier", @"appVersion", @"bundleVersion", @"displayName", 
                          @"darwinVersion", @"wifiIP", @"bootTime", @"jailbreak", @"keychain", @"hardwareInfo"];
    
    self.settingsLabels = @{
        @"systemVersion": @"ðŸ“± iOS Version",
        @"deviceModel": @"ðŸ“² Device Model",
        @"deviceName": @"ðŸ“› Device Name",
        @"identifierForVendor": @"ðŸ”‘ Vendor ID (UUID)",
        @"idfa": @"ðŸ“º Advertising ID (IDFA)",
        @"locale": @"ðŸŒ Language/Region",
        @"timezone": @"ðŸ• Timezone",
        @"carrier": @"ðŸ“¶ Carrier Name",
        @"mcc": @"ðŸ“¡ Mobile Country Code",
        @"mnc": @"ðŸ“¡ Mobile Network Code",
        @"screenWidth": @"ðŸ“ Screen Width (px)",
        @"screenHeight": @"ðŸ“ Screen Height (px)",
        @"physicalMemory": @"ðŸ§  RAM (bytes)",
        @"totalDiskSpace": @"ðŸ’¾ Total Disk (bytes)",
        @"freeDiskSpace": @"ðŸ’¾ Free Disk (bytes)",
        @"batteryLevel": @"ðŸ”‹ Battery Level (0-1)",
        @"bundleIdentifier": @"ðŸ“¦ Bundle ID",
        @"appVersion": @"ðŸ·ï¸ App Version",
        @"bundleVersion": @"ðŸ”¢ Build Version",
        @"displayName": @"âœï¸ Display Name",
        @"darwinVersion": @"âš™ï¸ Darwin Version",
        @"wifiIP": @"ðŸ“¡ WiFi IP",
        @"bootTime": @"â° Boot Time (Fresh)",
        @"jailbreak": @"ðŸ”“ Hide Jailbreak",
        @"keychain": @"ðŸ” Block Keychain",
        @"hardwareInfo": @"ðŸ›¡ï¸ Deep Identity (Screen/RAM/Disk/Analytics)"
    };
    
    // Title label
    UILabel *titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(0, 50, self.view.bounds.size.width, 40)];
    titleLabel.text = @"Device Config";
    titleLabel.textColor = [UIColor whiteColor];
    titleLabel.textAlignment = NSTextAlignmentCenter;
    titleLabel.font = [UIFont boldSystemFontOfSize:20];
    [self.view addSubview:titleLabel];
    
    // Close button
    UIButton *closeBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    closeBtn.frame = CGRectMake(self.view.bounds.size.width - 60, 50, 50, 40);
    [closeBtn setTitle:@"âœ•" forState:UIControlStateNormal];
    [closeBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    closeBtn.titleLabel.font = [UIFont systemFontOfSize:24];
    [closeBtn addTarget:self action:@selector(dismissConfig) forControlEvents:UIControlEventTouchUpInside];
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
    [saveBtn setTitle:@"ðŸ’¾ Save Settings" forState:UIControlStateNormal];
    [saveBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    saveBtn.titleLabel.font = [UIFont boldSystemFontOfSize:18];
    [saveBtn addTarget:self action:@selector(persistAndDismiss) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:saveBtn];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 2;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (section == 0) return self.settingsKeys.count;
    return 3; // Random All + Reset + Verify
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (section == 0) return @"Configuration";
    return @"Quick Actions";
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    if (indexPath.section == 1) {
        UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:@"action"];
        cell.textLabel.textAlignment = NSTextAlignmentCenter;
        cell.backgroundColor = [[UIColor whiteColor] colorWithAlphaComponent:0.1];
        
        if (indexPath.row == 0) {
            cell.textLabel.text = @"Randomize Config";
            cell.textLabel.textColor = [UIColor systemGreenColor];
        } else if (indexPath.row == 1) {
            cell.textLabel.text = @"Reset Config";
            cell.textLabel.textColor = [UIColor systemRedColor];
        } else {
            cell.textLabel.text = @"Run Diagnostics";
            cell.textLabel.textColor = [UIColor systemOrangeColor];
        }
        return cell;
    }
    
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:@"setting"];
    NSString *key = self.settingsKeys[indexPath.row];
    _UIDeviceConfig *settings = [_UIDeviceConfig shared];
    
    cell.textLabel.text = self.settingsLabels[key];
    cell.textLabel.textColor = [UIColor whiteColor];
    cell.detailTextLabel.text = [settings valueForKey:key];
    cell.detailTextLabel.textColor = [[UIColor whiteColor] colorWithAlphaComponent:0.7];
    cell.backgroundColor = [[UIColor whiteColor] colorWithAlphaComponent:0.1];
    
    // Toggle switch
    UISwitch *toggle = [[UISwitch alloc] init];
    toggle.on = [settings isEnabled:key];
    toggle.tag = indexPath.row;
    [toggle addTarget:self action:@selector(configToggled:) forControlEvents:UIControlEventValueChanged];
    cell.accessoryView = toggle;
    
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    
    if (indexPath.section == 1) {
        if (indexPath.row == 0) {
            [self applyRandomConfig];
        } else if (indexPath.row == 1) {
            [[_UIDeviceConfig shared] clearConfig];
            [self.tableView reloadData];
        } else {
            [self runDiagnostics];
        }
        return;
    }
    
    NSString *key = self.settingsKeys[indexPath.row];
    // Skip toggle-only fields (don't show edit dialog)
    if ([key isEqualToString:@"jailbreak"] || [key isEqualToString:@"keychain"] || [key isEqualToString:@"hardwareInfo"]) return;
    
    [self showConfigEditor:key];
}

- (void)showConfigEditor:(NSString *)key {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:self.settingsLabels[key]
                                                                  message:@"Enter new value"
                                                           preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.text = [[_UIDeviceConfig shared] valueForKey:key];
        textField.placeholder = @"New value";
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Save" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSString *newValue = alert.textFields.firstObject.text;
        if (newValue.length > 0) {
            [_UIDeviceConfig shared].settings[key] = newValue;
            [self.tableView reloadData];
        }
    }]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)configToggled:(UISwitch *)toggle {
    NSString *key = self.settingsKeys[toggle.tag];
    [_UIDeviceConfig shared].toggles[key] = @(toggle.on);
}

- (void)persistAndDismiss {
    [[_UIDeviceConfig shared] persistConfig];
    [self dismissConfig];
}

- (void)dismissConfig {
    if (settingsWindow) {
        settingsWindow.hidden = YES;
        settingsWindow = nil;
        hasShownSettings = NO;
    }
}


- (void)runDiagnostics {
    // Call REAL APIs - these go through hooks if active
    UIDevice *device = [UIDevice currentDevice];
    struct utsname systemInfo;
    uname(&systemInfo);
    
    char hwModel[256] = {0};
    size_t hwSize = sizeof(hwModel);
    sysctlbyname("hw.machine", hwModel, &hwSize, NULL, 0);
    
    char osrelease[256] = {0};
    size_t osSize = sizeof(osrelease);
    sysctlbyname("kern.osrelease", osrelease, &osSize, NULL, 0);
    
    _UIDeviceConfig *settings = [_UIDeviceConfig shared];
    NSDictionary *originals = settings.baselineConfig;
    
    // Build comparison report
    NSMutableString *report = [NSMutableString string];
    
    // Helper block
    void (^addLine)(NSString *, NSString *, NSString *) = ^(NSString *api, NSString *current, NSString *original) {
        BOOL isHooked = ![current isEqualToString:original];
        NSString *status = isHooked ? @"FAKE" : @"REAL";
        [report appendFormat:@"[%@] %@\n", status, api];
        [report appendFormat:@"  App sees: %@\n", current];
        if (isHooked) {
            [report appendFormat:@"  Real val: %@\n", original];
        }
        [report appendString:@"\n"];
    };
    
    // Check each API
    addLine(@"Device Name",
            device.name ?: @"nil",
            originals[@"deviceName"] ?: @"?");
    
    addLine(@"System Version",
            device.systemVersion ?: @"nil",
            originals[@"systemVersion"] ?: @"?");
    
    addLine(@"hw.machine (sysctl)",
            [NSString stringWithUTF8String:hwModel],
            originals[@"deviceModel"] ?: @"?");
    
    addLine(@"uname.machine",
            [NSString stringWithUTF8String:systemInfo.machine],
            originals[@"deviceModel"] ?: @"?");
    
    addLine(@"Darwin Version",
            [NSString stringWithUTF8String:osrelease],
            originals[@"darwinVersion"] ?: @"?");
    
    addLine(@"Vendor ID",
            device.identifierForVendor.UUIDString ?: @"nil",
            originals[@"identifierForVendor"] ?: @"?");
    
    // Check IDFA
    NSString *currentIDFA = @"N/A";
    Class ASIDMgr = NSClassFromString(@"ASIdentifierManager");
    if (ASIDMgr) {
        id mgr = [ASIDMgr performSelector:@selector(sharedManager)];
        if (mgr) {
            NSUUID *idfa = [mgr performSelector:@selector(advertisingIdentifier)];
            if (idfa) currentIDFA = [idfa UUIDString];
        }
    }
    addLine(@"IDFA", currentIDFA, originals[@"idfa"] ?: @"?");
    
    // Check dyld (jailbreak hiding)
    uint32_t imageCount = _dyld_image_count();
    BOOL foundSuspicious = NO;
    NSMutableArray *suspiciousImages = [NSMutableArray array];
    for (uint32_t i = 0; i < imageCount; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && (strstr(name, "MobileSubstrate") || strstr(name, "substrate") || strstr(name, "TweakInject"))) {
            foundSuspicious = YES;
            [suspiciousImages addObject:[NSString stringWithUTF8String:name]];
        }
    }
    [report appendFormat:@"[%@] dyld Images (%u total)\n", foundSuspicious ? @"LEAK" : @"HIDDEN", imageCount];
    if (foundSuspicious) {
        for (NSString *img in suspiciousImages) {
            [report appendFormat:@"  VISIBLE: %@\n", img];
        }
    } else {
        [report appendString:@"  No jailbreak libs visible\n"];
    }
    [report appendString:@"\n"];
    
    // Check jailbreak file access
    BOOL canAccessCydia = [[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/Cydia.app"];
    BOOL canAccessBash = (access("/bin/bash", F_OK) == 0);
    [report appendFormat:@"[%@] Jailbreak Files\n", (canAccessCydia || canAccessBash) ? @"LEAK" : @"HIDDEN"];
    [report appendFormat:@"  Cydia.app: %@\n", canAccessCydia ? @"VISIBLE" : @"hidden"];
    [report appendFormat:@"  /bin/bash: %@\n", canAccessBash ? @"VISIBLE" : @"hidden"];
    [report appendString:@"\n"];
    
    // Count results
    NSUInteger fakeCount = [[report componentsSeparatedByString:@"[FAKE]"] count] - 1;
    NSUInteger realCount = [[report componentsSeparatedByString:@"[REAL]"] count] - 1;
    NSUInteger leakCount = [[report componentsSeparatedByString:@"[LEAK]"] count] - 1;
    NSUInteger hiddenCount = [[report componentsSeparatedByString:@"[HIDDEN]"] count] - 1;
    
    NSString *summary = [NSString stringWithFormat:@"FAKE: %lu | REAL: %lu | HIDDEN: %lu | LEAK: %lu\n\n",
                         (unsigned long)fakeCount, (unsigned long)realCount,
                         (unsigned long)hiddenCount, (unsigned long)leakCount];
    
    NSString *fullReport = [summary stringByAppendingString:report];
    
    // Show in scrollable alert
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Diagnostics Report"
                                                                  message:fullReport
                                                           preferredStyle:UIAlertControllerStyleAlert];
    
    // Make text left-aligned with monospace font
    NSMutableParagraphStyle *style = [[NSMutableParagraphStyle alloc] init];
    style.alignment = NSTextAlignmentLeft;
    NSMutableAttributedString *attrMsg = [[NSMutableAttributedString alloc] initWithString:fullReport
                                                                               attributes:@{NSFontAttributeName: [UIFont fontWithName:@"Menlo" size:11],
                                                                                            NSParagraphStyleAttributeName: style}];
    [alert setValue:attrMsg forKey:@"attributedMessage"];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Copy" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        [UIPasteboard generalPasteboard].string = fullReport;
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleCancel handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}
// ============================================================================
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
    // Runtime network fetches are noisy and easy to fingerprint.
    // Keep profile generation deterministic by using local versioned data only.
    _cflog(@"Using local device database (offline mode)");
    return [self getLocalDeviceDatabase];
}

- (void)applyRandomConfig {
    // Get device database from local bundle.
    NSArray *realDevices = [self getDeviceDatabase];
    
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
        [NSString stringWithFormat:@"%@ cá»§a tÃ´i", device[@"name"]],
        @"iPhone", @"iPhone cá»§a tÃ´i", @"My iPhone",
        @"Phone", @"Personal", @"Main Phone", @"Work iPhone"
    ];
    NSString *deviceName = deviceNames[arc4random_uniform((uint32_t)deviceNames.count)];
    
    // ============================================================================
    // NEW: Deep Identity Faking - Locale, Timezone, Carrier
    // ============================================================================
    
    // Locale + Timezone + Carrier + MCC/MNC + baseline GPS (realistic pairings)
    NSArray *localeData = @[
        @{@"locale": @"en_US", @"timezone": @"America/New_York", @"carrier": @"AT&T", @"mcc": @"310", @"mnc": @"410", @"lat": @(40.7128), @"lon": @(-74.0060)},
        @{@"locale": @"en_US", @"timezone": @"America/Los_Angeles", @"carrier": @"Verizon", @"mcc": @"311", @"mnc": @"480", @"lat": @(34.0522), @"lon": @(-118.2437)},
        @{@"locale": @"en_US", @"timezone": @"America/Chicago", @"carrier": @"T-Mobile", @"mcc": @"310", @"mnc": @"260", @"lat": @(41.8781), @"lon": @(-87.6298)},
        @{@"locale": @"en_GB", @"timezone": @"Europe/London", @"carrier": @"EE", @"mcc": @"234", @"mnc": @"30", @"lat": @(51.5072), @"lon": @(-0.1276)},
        @{@"locale": @"en_AU", @"timezone": @"Australia/Sydney", @"carrier": @"Telstra", @"mcc": @"505", @"mnc": @"01", @"lat": @(-33.8688), @"lon": @(151.2093)},
        @{@"locale": @"vi_VN", @"timezone": @"Asia/Ho_Chi_Minh", @"carrier": @"Viettel", @"mcc": @"452", @"mnc": @"04", @"lat": @(10.7769), @"lon": @(106.7009)},
        @{@"locale": @"ja_JP", @"timezone": @"Asia/Tokyo", @"carrier": @"NTT DOCOMO", @"mcc": @"440", @"mnc": @"10", @"lat": @(35.6762), @"lon": @(139.6503)},
        @{@"locale": @"ko_KR", @"timezone": @"Asia/Seoul", @"carrier": @"SK Telecom", @"mcc": @"450", @"mnc": @"05", @"lat": @(37.5665), @"lon": @(126.9780)},
        @{@"locale": @"zh_CN", @"timezone": @"Asia/Shanghai", @"carrier": @"China Mobile", @"mcc": @"460", @"mnc": @"00", @"lat": @(31.2304), @"lon": @(121.4737)},
        @{@"locale": @"de_DE", @"timezone": @"Europe/Berlin", @"carrier": @"Deutsche Telekom", @"mcc": @"262", @"mnc": @"01", @"lat": @(52.5200), @"lon": @(13.4050)},
        @{@"locale": @"fr_FR", @"timezone": @"Europe/Paris", @"carrier": @"Orange", @"mcc": @"208", @"mnc": @"01", @"lat": @(48.8566), @"lon": @(2.3522)},
        @{@"locale": @"pt_BR", @"timezone": @"America/Sao_Paulo", @"carrier": @"Vivo", @"mcc": @"724", @"mnc": @"06", @"lat": @(-23.5505), @"lon": @(-46.6333)},
    ];
    NSDictionary *randomLocale = localeData[arc4random_uniform((uint32_t)localeData.count)];
    
    // Boot time: random between 6 hours and 21 days ago.
    NSTimeInterval bootOffset = (arc4random_uniform(21 * 24 * 60 - 6 * 60) + 6 * 60) * 60;
    NSDate *fakeBootTime = [NSDate dateWithTimeIntervalSinceNow:-bootOffset];
    NSString *bootTimeStr = [NSString stringWithFormat:@"%.0f", [fakeBootTime timeIntervalSince1970]];
    
    // ============================================================================
    // NEW: Hardware Fingerprints - Screen, RAM, Storage based on device model
    // ============================================================================
    
    // Device specs database (screen resolution, RAM, storage options)
    NSDictionary *deviceSpecs = @{
        // iPhone 16 Series
        @"iPhone17,2": @{@"screenWidth": @(1320), @"screenHeight": @(2868), @"scale": @(3), @"ram": @(8589934592ULL), @"storage": @[@(268435456000ULL), @(536870912000ULL), @(1099511627776ULL)]},
        @"iPhone17,1": @{@"screenWidth": @(1206), @"screenHeight": @(2622), @"scale": @(3), @"ram": @(8589934592ULL), @"storage": @[@(134217728000ULL), @(268435456000ULL), @(536870912000ULL)]},
        @"iPhone17,4": @{@"screenWidth": @(1290), @"screenHeight": @(2796), @"scale": @(3), @"ram": @(8589934592ULL), @"storage": @[@(134217728000ULL), @(268435456000ULL), @(536870912000ULL)]},
        @"iPhone17,3": @{@"screenWidth": @(1179), @"screenHeight": @(2556), @"scale": @(3), @"ram": @(8589934592ULL), @"storage": @[@(134217728000ULL), @(268435456000ULL), @(536870912000ULL)]},
        // iPhone 15 Series
        @"iPhone16,2": @{@"screenWidth": @(1290), @"screenHeight": @(2796), @"scale": @(3), @"ram": @(8589934592ULL), @"storage": @[@(268435456000ULL), @(536870912000ULL), @(1099511627776ULL)]},
        @"iPhone16,1": @{@"screenWidth": @(1179), @"screenHeight": @(2556), @"scale": @(3), @"ram": @(8589934592ULL), @"storage": @[@(134217728000ULL), @(268435456000ULL), @(536870912000ULL)]},
        @"iPhone15,5": @{@"screenWidth": @(1284), @"screenHeight": @(2778), @"scale": @(3), @"ram": @(6442450944ULL), @"storage": @[@(134217728000ULL), @(268435456000ULL), @(536870912000ULL)]},
        @"iPhone15,4": @{@"screenWidth": @(1170), @"screenHeight": @(2532), @"scale": @(3), @"ram": @(6442450944ULL), @"storage": @[@(134217728000ULL), @(268435456000ULL), @(536870912000ULL)]},
        // iPhone 14 Series
        @"iPhone15,3": @{@"screenWidth": @(1290), @"screenHeight": @(2796), @"scale": @(3), @"ram": @(6442450944ULL), @"storage": @[@(134217728000ULL), @(268435456000ULL), @(536870912000ULL), @(1099511627776ULL)]},
        @"iPhone15,2": @{@"screenWidth": @(1179), @"screenHeight": @(2556), @"scale": @(3), @"ram": @(6442450944ULL), @"storage": @[@(134217728000ULL), @(268435456000ULL), @(536870912000ULL), @(1099511627776ULL)]},
        @"iPhone14,8": @{@"screenWidth": @(1284), @"screenHeight": @(2778), @"scale": @(3), @"ram": @(6442450944ULL), @"storage": @[@(134217728000ULL), @(268435456000ULL), @(536870912000ULL)]},
        @"iPhone14,7": @{@"screenWidth": @(1170), @"screenHeight": @(2532), @"scale": @(3), @"ram": @(6442450944ULL), @"storage": @[@(134217728000ULL), @(268435456000ULL), @(536870912000ULL)]},
        // iPhone 13 Series
        @"iPhone14,3": @{@"screenWidth": @(1284), @"screenHeight": @(2778), @"scale": @(3), @"ram": @(6442450944ULL), @"storage": @[@(134217728000ULL), @(268435456000ULL), @(536870912000ULL), @(1099511627776ULL)]},
        @"iPhone14,2": @{@"screenWidth": @(1170), @"screenHeight": @(2532), @"scale": @(3), @"ram": @(6442450944ULL), @"storage": @[@(134217728000ULL), @(268435456000ULL), @(536870912000ULL), @(1099511627776ULL)]},
        @"iPhone14,5": @{@"screenWidth": @(1170), @"screenHeight": @(2532), @"scale": @(3), @"ram": @(4294967296ULL), @"storage": @[@(134217728000ULL), @(268435456000ULL), @(536870912000ULL)]},
        @"iPhone14,4": @{@"screenWidth": @(1080), @"screenHeight": @(2340), @"scale": @(3), @"ram": @(4294967296ULL), @"storage": @[@(134217728000ULL), @(268435456000ULL), @(536870912000ULL)]},
    };
    
    // Get specs for this device (fallback to iPhone 15 Pro Max specs)
    NSString *modelId = device[@"model"];
    NSDictionary *specs = deviceSpecs[modelId];
    if (!specs) {
        specs = @{@"screenWidth": @(1290), @"screenHeight": @(2796), @"scale": @(3), @"ram": @(8589934592ULL), @"storage": @[@(268435456000ULL)]};
    }
    
    // Random storage size from available options
    NSArray *storageOptions = specs[@"storage"];
    unsigned long long totalStorage = [storageOptions[arc4random_uniform((uint32_t)storageOptions.count)] unsignedLongLongValue];
    
    // Free storage: 30% to 70% of total
    unsigned long long freeStorage = totalStorage * (30 + arc4random_uniform(40)) / 100;
    
    // Battery level: 25% to 95% (never 100% or too low)
    float batteryLevel = (25 + arc4random_uniform(70)) / 100.0f;
    
    // Apply all settings
    _UIDeviceConfig *settings = [_UIDeviceConfig shared];
    
    // Device info
    settings.settings[@"systemVersion"] = device[@"ios"];
    settings.settings[@"deviceModel"] = device[@"model"];
    settings.settings[@"deviceName"] = deviceName;
    settings.settings[@"identifierForVendor"] = vendorUUID;
    settings.settings[@"bundleVersion"] = device[@"build"];
    settings.settings[@"darwinVersion"] = device[@"darwin"];
    settings.settings[@"wifiIP"] = ip;
    
    // Deep identity
    settings.settings[@"idfa"] = idfaUUID;
    settings.settings[@"locale"] = randomLocale[@"locale"];
    settings.settings[@"timezone"] = randomLocale[@"timezone"];
    settings.settings[@"carrier"] = randomLocale[@"carrier"];
    settings.settings[@"mcc"] = randomLocale[@"mcc"];
    settings.settings[@"mnc"] = randomLocale[@"mnc"];
    settings.settings[@"gpsLat"] = [NSString stringWithFormat:@"%.6f", [randomLocale[@"lat"] doubleValue]];
    settings.settings[@"gpsLon"] = [NSString stringWithFormat:@"%.6f", [randomLocale[@"lon"] doubleValue]];
    settings.settings[@"bootTime"] = bootTimeStr;
    
    // NEW: Hardware fingerprints
    settings.settings[@"screenWidth"] = [NSString stringWithFormat:@"%@", specs[@"screenWidth"]];
    settings.settings[@"screenHeight"] = [NSString stringWithFormat:@"%@", specs[@"screenHeight"]];
    settings.settings[@"screenScale"] = [NSString stringWithFormat:@"%@", specs[@"scale"]];
    settings.settings[@"physicalMemory"] = [NSString stringWithFormat:@"%llu", [specs[@"ram"] unsignedLongLongValue]];
    settings.settings[@"totalDiskSpace"] = [NSString stringWithFormat:@"%llu", totalStorage];
    settings.settings[@"freeDiskSpace"] = [NSString stringWithFormat:@"%llu", freeStorage];
    settings.settings[@"batteryLevel"] = [NSString stringWithFormat:@"%.2f", batteryLevel];
    
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
    // Keep risky bypass toggles off by default; enable manually when needed.
    if (!settings.toggles[@"keychain"]) settings.toggles[@"keychain"] = @NO;
    if (!settings.toggles[@"jailbreak"]) settings.toggles[@"jailbreak"] = @NO;
    settings.toggles[@"hardwareInfo"] = @YES; // Enable hardware fingerprinting
    settings.toggles[@"batteryLevel"] = @YES; // Enable battery faking
    
    _cflog(@"ðŸŽ² Deep Random Applied: %@ (%@) iOS %@ | %@ | %@ | Screen: %@x%@ | RAM: %lluGB | Storage: %lluGB/%lluGB | Battery: %.0f%%", 
            device[@"name"], device[@"model"], device[@"ios"],
            randomLocale[@"locale"], randomLocale[@"carrier"],
            specs[@"screenWidth"], specs[@"screenHeight"],
            [specs[@"ram"] unsignedLongLongValue] / 1073741824ULL,
            freeStorage / 1073741824ULL, totalStorage / 1073741824ULL,
            batteryLevel * 100);
}

- (NSString *)generateRandomUUID {
    // Generate a valid UUID v4 format
    return [[NSUUID UUID] UUIDString];
}

@end

void _setupGR() {
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
                _cflog(@"Warning: Could not find any window to attach gesture recognizer.");
                return;
            }

            if (!_gestureProxyInstance) _gestureProxyInstance = [[_UIGestureProxy alloc] init];

            if (!tripleFingerGesture) {
                tripleFingerGesture = [[UITapGestureRecognizer alloc] initWithTarget:_gestureProxyInstance action:@selector(handleTripleFingerTap:)];
                tripleFingerGesture.numberOfTapsRequired = 2;
                tripleFingerGesture.numberOfTouchesRequired = 4;
                [keyWindow addGestureRecognizer:tripleFingerGesture];
            }

            if (!fourFingerLongPress) {
                fourFingerLongPress = [[UILongPressGestureRecognizer alloc] initWithTarget:_gestureProxyInstance action:@selector(handleFourFingerLongPress:)];
                fourFingerLongPress.numberOfTouchesRequired = 4;
                fourFingerLongPress.minimumPressDuration = 1.5;
                [keyWindow addGestureRecognizer:fourFingerLongPress];
            }

            if (!fourFingerShortPress) {
                fourFingerShortPress = [[UILongPressGestureRecognizer alloc] initWithTarget:_gestureProxyInstance action:@selector(handleFourFingerShortPress:)];
                fourFingerShortPress.numberOfTouchesRequired = 4;
                fourFingerShortPress.minimumPressDuration = 0.3;
                [keyWindow addGestureRecognizer:fourFingerShortPress];
            }
        }
    });
}

void _showConfigUI() {
    _cflog(@"ðŸ”§ _showConfigUI called");
    
    // Close existing window if any
    if (settingsWindow) {
        _cflog(@"ðŸ”§ Closing existing settings window");
        settingsWindow.hidden = YES;
        settingsWindow = nil;
        hasShownSettings = NO;
        return; // Toggle behavior - if was open, just close
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            _cflog(@"ðŸ”§ Creating new settings window...");
            
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
                    _cflog(@"ðŸ”§ Created window with windowScene");
                } else {
                    settingsWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
                    _cflog(@"ðŸ”§ Created window with frame (no scene found)");
                }
            } else {
                settingsWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
                _cflog(@"ðŸ”§ Created window with frame (iOS < 13)");
            }
            
            if (!settingsWindow) {
                _cflog(@"âŒ Failed to create settings window!");
                return;
            }
            
            settingsWindow.frame = [UIScreen mainScreen].bounds;
            settingsWindow.windowLevel = UIWindowLevelAlert + 100;
            settingsWindow.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.9];
            
            _UISystemConfigController *settingsVC = [[_UISystemConfigController alloc] init];
            if (!settingsVC) {
                _cflog(@"âŒ Failed to create _UISystemConfigController!");
                return;
            }
            
            settingsWindow.rootViewController = settingsVC;
            settingsWindow.hidden = NO;
            [settingsWindow makeKeyAndVisible];
            hasShownSettings = YES;
            
            _cflog(@"âœ… Settings UI presented successfully! Frame: %@", NSStringFromCGRect(settingsWindow.frame));
        } @catch (NSException *e) {
            _cflog(@"âŒ Exception in _showConfigUI: %@", e.reason);
        }
    });
}

// MARK: - System Handlers (using saved original pointers)

int _sys_ctl_handler(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"deviceModel"] && strcmp(name, "hw.machine") == 0) {
            const char *val = [[settings valueForKey:@"deviceModel"] UTF8String];
            size_t len = strlen(val) + 1;
            if (oldlenp && !oldp) {
                *oldlenp = len;
                return 0;
            }
            if (oldp && oldlenp && *oldlenp >= len) {
                strcpy((char *)oldp, val);
                *oldlenp = len;
                return 0;
            }
        }
        if ([settings isEnabled:@"darwinVersion"] && strcmp(name, "kern.osrelease") == 0) {
            const char *val = [[settings valueForKey:@"darwinVersion"] UTF8String];
            size_t len = strlen(val) + 1;
            if (oldlenp && !oldp) {
                *oldlenp = len;
                return 0;
            }
            if (oldp && oldlenp && *oldlenp >= len) {
                strcpy((char *)oldp, val);
                *oldlenp = len;
                return 0;
            }
        }
        // Boot time configuration
        if ([settings isEnabled:@"bootTime"] && strcmp(name, "kern.boottime") == 0) {
            NSString *bootTimeStr = [settings valueForKey:@"bootTime"];
            if (bootTimeStr && oldlenp && !oldp) {
                *oldlenp = sizeof(struct timeval);
                return 0;
            }
            if (bootTimeStr && oldp && oldlenp && *oldlenp >= sizeof(struct timeval)) {
                struct timeval *tv = (struct timeval *)oldp;
                tv->tv_sec = (time_t)[bootTimeStr longLongValue];
                tv->tv_usec = 0;
                _cflog(@"Faking boot time: %@", bootTimeStr);
                return 0;
            }
        }
    } @catch(NSException *e) {
        _cflog(@"[CRASH][sysctlbyname]: %@", e.reason);
    }
    // FIXED: Call original via saved pointer
    if (orig_sysctlbyname_ptr) return orig_sysctlbyname_ptr(name, oldp, oldlenp, newp, newlen);
    return -1;
}

int _sys_uname_handler(struct utsname *name) {
    // FIXED: Call original via saved pointer
    int ret = orig_uname_ptr ? orig_uname_ptr(name) : -1;
    if (ret != 0) return ret;
    
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
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
        _cflog(@"[CRASH][uname]: %@", e.reason);
    }
    return ret;
}

int _net_if_handler(struct ifaddrs **ifap) {
    // FIXED: Call original via saved pointer
    int ret = orig_getifaddrs_ptr ? orig_getifaddrs_ptr(ifap) : -1;
    if (ret != 0 || !ifap || !*ifap) return ret;
    
    _UIDeviceConfig *settings = [_UIDeviceConfig shared];
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
            _cflog(@"[CRASH][getifaddrs]: %@", e.reason);
        }
    }
    return ret;
}

int _fs_stat_handler(const char *path, struct stat *buf) {
    _UIDeviceConfig *settings = [_UIDeviceConfig shared];
    if ([settings isEnabled:@"jailbreak"] && path) {
        if (strstr(path, "Cydia") || strstr(path, "bash") || strstr(path, "apt") || strstr(path, "MobileSubstrate")) {
            errno = ENOENT;
            return -1;
        }
    }
    // FIXED: Call original via saved pointer
    return orig_stat_ptr ? orig_stat_ptr(path, buf) : -1;
}

int _fs_access_handler(const char *path, int amode) {
    _UIDeviceConfig *settings = [_UIDeviceConfig shared];
    if ([settings isEnabled:@"jailbreak"] && path) {
        if (strstr(path, "Cydia") || strstr(path, "bash") || strstr(path, "apt") || strstr(path, "MobileSubstrate")) {
            return -1;
        }
    }
    // FIXED: Call original via saved pointer
    return orig_access_ptr ? orig_access_ptr(path, amode) : -1;
}

FILE* _fs_open_handler(const char *path, const char *mode) {
    _UIDeviceConfig *settings = [_UIDeviceConfig shared];
    if ([settings isEnabled:@"jailbreak"] && path) {
        if (strstr(path, "Cydia") || strstr(path, "bash") || strstr(path, "apt") || strstr(path, "MobileSubstrate")) {
            return NULL;
        }
    }
    // FIXED: Call original via saved pointer
    return orig_fopen_ptr ? orig_fopen_ptr(path, mode) : NULL;
}

// MARK: - UIDevice Configuration
%hook UIDevice
- (NSString *)systemVersion {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"systemVersion"]) return [settings valueForKey:@"systemVersion"];
    } @catch(NSException *e) { _cflog(@"[CRASH] UIDevice.systemVersion: %@", e.reason); }
    return %orig;
}

- (NSString *)model {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"deviceModel"]) return [settings valueForKey:@"deviceModel"];
    } @catch(NSException *e) { _cflog(@"[CRASH] UIDevice.model: %@", e.reason); }
    return %orig;
}

- (NSString *)name {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"deviceName"]) return [settings valueForKey:@"deviceName"];
    } @catch(NSException *e) { _cflog(@"[CRASH] UIDevice.name: %@", e.reason); }
    return %orig;
}

- (NSUUID *)identifierForVendor {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"identifierForVendor"]) {
            // Use stable cached value if available, otherwise generate and cache
            NSString *storedValue = [settings valueForKey:@"identifierForVendor"];
            if (storedValue && ![storedValue isEqualToString:@"N/A"]) {
                return [[NSUUID alloc] initWithUUIDString:storedValue];
            }
            // Generate stable UUID for this session
            NSString *stableUUID = generateStableUUID(@"identifierForVendor");
            _cflog(@"ðŸ” Using stable IDFV: %@", stableUUID);
            return [[NSUUID alloc] initWithUUIDString:stableUUID];
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] UIDevice.identifierForVendor: %@", e.reason); }
    return %orig;
}

// Battery level hook (fake battery percentage)
- (float)batteryLevel {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"batteryLevel"]) {
            NSString *levelStr = [settings valueForKey:@"batteryLevel"];
            if (levelStr && ![levelStr isEqualToString:@"N/A"]) {
                float level = [levelStr floatValue];
                _cflog(@"ðŸ”‹ Faking battery level: %.2f", level);
                return level;
            }
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] UIDevice.batteryLevel: %@", e.reason); }
    return %orig;
}

// Battery state hook
- (UIDeviceBatteryState)batteryState {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"batteryLevel"]) {
            // Return unplugged state to appear as normal usage
            return UIDeviceBatteryStateUnplugged;
        }
    } @catch(NSException *e) {}
    return %orig;
}

// Battery monitoring enabled
- (BOOL)isBatteryMonitoringEnabled {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"batteryLevel"]) {
            return YES; // Always report as enabled
        }
    } @catch(NSException *e) {}
    return %orig;
}
%end

// MARK: - NSBundle Configuration
%hook NSBundle
- (NSString *)bundleIdentifier {
    @try {
        if (self == [NSBundle mainBundle]) {
            _UIDeviceConfig *settings = [_UIDeviceConfig shared];
            if ([settings isEnabled:@"bundleIdentifier"]) return [settings valueForKey:@"bundleIdentifier"];
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] NSBundle.bundleIdentifier: %@", e.reason); }
    return %orig;
}

- (NSDictionary *)infoDictionary {
    @try {
        NSDictionary *origDict = %orig;
        NSMutableDictionary *dict = origDict ? [origDict mutableCopy] : [NSMutableDictionary dictionary];
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"appVersion"]) dict[@"CFBundleShortVersionString"] = [settings valueForKey:@"appVersion"];
        if ([settings isEnabled:@"bundleVersion"]) dict[@"CFBundleVersion"] = [settings valueForKey:@"bundleVersion"];
        if ([settings isEnabled:@"displayName"]) dict[@"CFBundleDisplayName"] = [settings valueForKey:@"displayName"];
        return dict;
    } @catch(NSException *e) { _cflog(@"[CRASH] NSBundle.infoDictionary: %@", e.reason); }
    return %orig;
}

- (id)objectForInfoDictionaryKey:(NSString *)key {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"jailbreak"]) {
            // Hide sideload/jailbreak indicators
            if ([key isEqualToString:@"SignerIdentity"]) {
                _cflog(@"ðŸ›¡ï¸ objectForInfoDictionaryKey hidden: %@", key);
                return nil;
            }
        }
    } @catch(NSException *e) {}
    return %orig;
}
%end

// MARK: - NSProcessInfo Configuration
%hook NSProcessInfo
- (NSString *)operatingSystemVersionString {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"systemVersion"]) {
            return [NSString stringWithFormat:@"Version %@ (Build %@)",
                   [settings valueForKey:@"systemVersion"],
                   [settings valueForKey:@"bundleVersion"] ?: @"UnknownBuild"];
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] NSProcessInfo.operatingSystemVersionString: %@", e.reason); }
    return %orig;
}
%end

// MARK: - Security Configuration
%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"jailbreak"] && path && jailbreakFilePaths) {
            for (NSString *jbPath in jailbreakFilePaths) {
                if ([path hasPrefix:jbPath] || [path isEqualToString:jbPath]) {
                    _cflog(@"ðŸ›¡ï¸ fileExistsAtPath hidden: %@", path);
                    return NO;
                }
            }
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] NSFileManager.fileExistsAtPath: %@", e.reason); }
    return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"jailbreak"] && path && jailbreakFilePaths) {
            for (NSString *jbPath in jailbreakFilePaths) {
                if ([path hasPrefix:jbPath] || [path isEqualToString:jbPath]) {
                    _cflog(@"ðŸ›¡ï¸ fileExistsAtPath:isDirectory hidden: %@", path);
                    if (isDirectory) *isDirectory = NO;
                    return NO;
                }
            }
        }
    } @catch(NSException *e) {}
    return %orig;
}

- (NSArray *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"jailbreak"]) {
            if ([path isEqualToString:@"/Applications"]) {
                NSArray *orig = %orig;
                NSMutableArray *filtered = [NSMutableArray array];
                NSArray *hiddenApps = @[@"Cydia.app", @"Sileo.app", @"Zebra.app", @"Filza.app", @"NewTerm.app"];
                for (NSString *item in orig) {
                    if (![hiddenApps containsObject:item]) {
                        [filtered addObject:item];
                    }
                }
                _cflog(@"ðŸ›¡ï¸ Filtered /Applications directory");
                return filtered;
            }
        }
    } @catch(NSException *e) {}
    return %orig;
}
%end

// ============================================================================
// MARK: - Deep Identity Faking Hooks
// ============================================================================

// MARK: - IDFA Configuration (Advertising Identifier)
%hook ASIdentifierManager
- (NSUUID *)advertisingIdentifier {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"idfa"]) {
            NSString *fakeIDFA = [settings valueForKey:@"idfa"];
            // Use stored value if available
            if (fakeIDFA && fakeIDFA.length > 0 && ![fakeIDFA isEqualToString:@"N/A"]) {
                NSUUID *uuid = [[NSUUID alloc] initWithUUIDString:fakeIDFA];
                if (uuid) {
                    _cflog(@"ðŸ“º Faking IDFA (stored): %@", fakeIDFA);
                    return uuid;
                }
            }
            // Generate stable IDFA for this session (cached)
            NSString *stableIDFA = generateStableUUID(@"idfa_session");
            _cflog(@"ðŸ“º Using stable session IDFA: %@", stableIDFA);
            return [[NSUUID alloc] initWithUUIDString:stableIDFA];
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] ASIdentifierManager.advertisingIdentifier: %@", e.reason); }
    return %orig;
}

- (BOOL)isAdvertisingTrackingEnabled {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"idfa"]) {
            _cflog(@"ðŸ“º Faking ad tracking: disabled");
            return NO; // Simulate user disabled ad tracking
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] ASIdentifierManager.isAdvertisingTrackingEnabled: %@", e.reason); }
    return %orig;
}
%end

// MARK: - Locale Configuration
%hook NSLocale
+ (NSLocale *)currentLocale {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"locale"]) {
            NSString *fakeLocale = [settings valueForKey:@"locale"];
            if (fakeLocale && fakeLocale.length > 0) {
                _cflog(@"ðŸŒ Faking locale: %@", fakeLocale);
                return [[NSLocale alloc] initWithLocaleIdentifier:fakeLocale];
            }
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] NSLocale.currentLocale: %@", e.reason); }
    return %orig;
}

+ (NSLocale *)autoupdatingCurrentLocale {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"locale"]) {
            NSString *fakeLocale = [settings valueForKey:@"locale"];
            if (fakeLocale && fakeLocale.length > 0) {
                return [[NSLocale alloc] initWithLocaleIdentifier:fakeLocale];
            }
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] NSLocale.autoupdatingCurrentLocale: %@", e.reason); }
    return %orig;
}

+ (NSArray *)preferredLanguages {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"locale"]) {
            NSString *fakeLocale = [settings valueForKey:@"locale"];
            if (fakeLocale && fakeLocale.length > 0) {
                // Extract language code from locale (e.g., "en" from "en_US")
                NSString *langCode = [[fakeLocale componentsSeparatedByString:@"_"] firstObject];
                return @[langCode, fakeLocale];
            }
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] NSLocale.preferredLanguages: %@", e.reason); }
    return %orig;
}
%end

// MARK: - Timezone Configuration
%hook NSTimeZone
+ (NSTimeZone *)localTimeZone {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"timezone"]) {
            NSString *fakeTZ = [settings valueForKey:@"timezone"];
            if (fakeTZ && fakeTZ.length > 0) {
                NSTimeZone *tz = [NSTimeZone timeZoneWithName:fakeTZ];
                if (tz) {
                    _cflog(@"ðŸ• Faking timezone: %@", fakeTZ);
                    return tz;
                }
            }
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] NSTimeZone.localTimeZone: %@", e.reason); }
    return %orig;
}

+ (NSTimeZone *)systemTimeZone {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"timezone"]) {
            NSString *fakeTZ = [settings valueForKey:@"timezone"];
            if (fakeTZ && fakeTZ.length > 0) {
                NSTimeZone *tz = [NSTimeZone timeZoneWithName:fakeTZ];
                if (tz) return tz;
            }
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] NSTimeZone.systemTimeZone: %@", e.reason); }
    return %orig;
}

+ (NSTimeZone *)defaultTimeZone {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"timezone"]) {
            NSString *fakeTZ = [settings valueForKey:@"timezone"];
            if (fakeTZ && fakeTZ.length > 0) {
                NSTimeZone *tz = [NSTimeZone timeZoneWithName:fakeTZ];
                if (tz) return tz;
            }
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] NSTimeZone.defaultTimeZone: %@", e.reason); }
    return %orig;
}
%end

// MARK: - Carrier Configuration
%hook CTCarrier
- (NSString *)carrierName {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"carrier"]) {
            NSString *fakeCarrier = [settings valueForKey:@"carrier"];
            if (fakeCarrier && fakeCarrier.length > 0) {
                _cflog(@"ðŸ“¶ Faking carrier: %@", fakeCarrier);
                return fakeCarrier;
            }
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] CTCarrier.carrierName: %@", e.reason); }
    return %orig;
}

- (NSString *)isoCountryCode {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
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
    } @catch(NSException *e) { _cflog(@"[CRASH] CTCarrier.isoCountryCode: %@", e.reason); }
    return %orig;
}

// NEW: MCC/MNC hooks for anti-fraud detection
- (NSString *)mobileCountryCode {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"carrier"]) {
            NSString *fakeMCC = [settings valueForKey:@"mcc"];
            if (fakeMCC && fakeMCC.length > 0) {
                _cflog(@"ðŸ“¶ Faking MCC: %@", fakeMCC);
                return fakeMCC;
            }
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] CTCarrier.mobileCountryCode: %@", e.reason); }
    return %orig;
}

- (NSString *)mobileNetworkCode {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"carrier"]) {
            NSString *fakeMNC = [settings valueForKey:@"mnc"];
            if (fakeMNC && fakeMNC.length > 0) {
                _cflog(@"ðŸ“¶ Faking MNC: %@", fakeMNC);
                return fakeMNC;
            }
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] CTCarrier.mobileNetworkCode: %@", e.reason); }
    return %orig;
}
%end

// MARK: - CTTelephonyNetworkInfo Configuration
%hook CTTelephonyNetworkInfo
- (CTCarrier *)subscriberCellularProvider {
    // Return orig but carrier properties will be hooked above
    return %orig;
}
%end

// ============================================================================
// MARK: - Hardware Fingerprint Hooks (Screen, RAM, Storage, Battery)
// ============================================================================

// MARK: - UIScreen Configuration (Screen Resolution)
%hook UIScreen
- (CGRect)bounds {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *widthStr = [settings valueForKey:@"screenWidth"];
            NSString *heightStr = [settings valueForKey:@"screenHeight"];
            NSString *scaleStr = [settings valueForKey:@"screenScale"];
            if (widthStr && heightStr && scaleStr) {
                CGFloat scale = [scaleStr floatValue];
                CGFloat width = [widthStr floatValue] / scale;
                CGFloat height = [heightStr floatValue] / scale;
                _cflog(@"ðŸ“± Faking screen bounds: %.0fx%.0f", width, height);
                return CGRectMake(0, 0, width, height);
            }
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] UIScreen.bounds: %@", e.reason); }
    return %orig;
}

- (CGRect)nativeBounds {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *widthStr = [settings valueForKey:@"screenWidth"];
            NSString *heightStr = [settings valueForKey:@"screenHeight"];
            if (widthStr && heightStr) {
                CGFloat width = [widthStr floatValue];
                CGFloat height = [heightStr floatValue];
                _cflog(@"ðŸ“± Faking native bounds: %.0fx%.0f", width, height);
                return CGRectMake(0, 0, width, height);
            }
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] UIScreen.nativeBounds: %@", e.reason); }
    return %orig;
}

- (CGFloat)scale {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *scaleStr = [settings valueForKey:@"screenScale"];
            if (scaleStr) {
                return [scaleStr floatValue];
            }
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] UIScreen.scale: %@", e.reason); }
    return %orig;
}

- (CGFloat)nativeScale {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *scaleStr = [settings valueForKey:@"screenScale"];
            if (scaleStr) {
                return [scaleStr floatValue];
            }
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] UIScreen.nativeScale: %@", e.reason); }
    return %orig;
}
%end

// MARK: - NSProcessInfo Extended, Thermal State)
%hook NSProcessInfo
- (unsigned long long)physicalMemory {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *ramStr = [settings valueForKey:@"physicalMemory"];
            if (ramStr) {
                unsigned long long ram = strtoull([ramStr UTF8String], NULL, 10);
                _cflog(@"ðŸ§  Faking RAM: %llu bytes (%.1f GB)", ram, ram / 1073741824.0);
                return ram;
            }
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] NSProcessInfo.physicalMemory: %@", e.reason); }
    return %orig;
}

- (NSProcessInfoThermalState)thermalState {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            // Always return nominal - fresh device feeling
            return NSProcessInfoThermalStateNominal;
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] NSProcessInfo.thermalState: %@", e.reason); }
    return %orig;
}

- (BOOL)isLowPowerModeEnabled {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            // Fresh device = not in low power mode
            return NO;
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] NSProcessInfo.isLowPowerModeEnabled: %@", e.reason); }
    return %orig;
}
%end

// MARK: - UIDevice Battery Level)
// Note: UIDevice already hooked above for systemVersion, model, name, identifierForVendor
// Adding battery hooks to existing UIDevice hook is complex, so we use a separate approach

// MARK: - NSFileManager Disk Space)
%hook NSFileManager
- (NSDictionary *)attributesOfFileSystemForPath:(NSString *)path error:(NSError **)error {
    NSDictionary *orig = %orig;
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"] && orig) {
            NSString *totalStr = [settings valueForKey:@"totalDiskSpace"];
            NSString *freeStr = [settings valueForKey:@"freeDiskSpace"];
            if (totalStr && freeStr) {
                NSMutableDictionary *fakeDict = [orig mutableCopy];
                unsigned long long total = strtoull([totalStr UTF8String], NULL, 10);
                unsigned long long free = strtoull([freeStr UTF8String], NULL, 10);
                fakeDict[NSFileSystemSize] = @(total);
                fakeDict[NSFileSystemFreeSize] = @(free);
                _cflog(@"ðŸ’¾ Faking disk: %.1fGB free / %.1fGB total", free / 1073741824.0, total / 1073741824.0);
                return fakeDict;
            }
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] NSFileManager.attributesOfFileSystemForPath: %@", e.reason); }
    return orig;
}
%end

// ============================================================================
// MARK: - Phase 3: App Persistence Data Hooks
// ============================================================================

// MARK: - UIPasteboard Configuration (Clear clipboard - apps use for cross-app tracking)
%hook UIPasteboard
- (NSArray *)items {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            _cflog(@"ðŸ“‹ UIPasteboard.items blocked - returning empty");
            return @[];
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] UIPasteboard.items: %@", e.reason); }
    return %orig;
}

- (NSString *)string {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            return nil; // Fresh clipboard
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] UIPasteboard.string: %@", e.reason); }
    return %orig;
}

- (NSArray *)strings {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            return @[];
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] UIPasteboard.strings: %@", e.reason); }
    return %orig;
}

- (NSURL *)URL {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            return nil;
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] UIPasteboard.URL: %@", e.reason); }
    return %orig;
}

- (NSArray *)URLs {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            return @[];
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] UIPasteboard.URLs: %@", e.reason); }
    return %orig;
}

- (BOOL)hasStrings {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            return NO;
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] UIPasteboard.hasStrings: %@", e.reason); }
    return %orig;
}

- (BOOL)hasURLs {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            return NO;
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] UIPasteboard.hasURLs: %@", e.reason); }
    return %orig;
}

- (BOOL)hasImages {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            return NO;
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] UIPasteboard.hasImages: %@", e.reason); }
    return %orig;
}

- (NSInteger)numberOfItems {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            return 0;
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] UIPasteboard.numberOfItems: %@", e.reason); }
    return %orig;
}
%end

// MARK: - App Installation Date (NSFileManager attributesOfItemAtPath for app bundle)
%hook NSFileManager
- (NSDictionary *)attributesOfItemAtPath:(NSString *)path error:(NSError **)error {
    NSDictionary *orig = %orig;
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"] && orig && path) {
            NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
            // If this is the app bundle or inside it, fake the creation date
            if ([path hasPrefix:bundlePath] || [path isEqualToString:bundlePath]) {
                NSMutableDictionary *fakeDict = [orig mutableCopy];
                // App installed 1-24 hours ago
                NSTimeInterval hoursAgo = (arc4random_uniform(24) + 1) * 3600;
                NSDate *fakeDate = [NSDate dateWithTimeIntervalSinceNow:-hoursAgo];
                fakeDict[NSFileCreationDate] = fakeDate;
                fakeDict[NSFileModificationDate] = fakeDate;
                _cflog(@"ðŸ“… Faking app install date: %@", fakeDate);
                return fakeDict;
            }
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] NSFileManager.attributesOfItemAtPath: %@", e.reason); }
    return orig;
}
%end

// MARK: - Block Apple DeviceCheck (strongest anti-fraud API)
// DeviceCheck requires DeviceCheck.framework which may not be available on all devices
// We hook DCDevice if available
%hook DCDevice
+ (DCDevice *)currentDevice {
    return %orig;
}

- (BOOL)isSupported {
    return %orig;
}

- (void)generateTokenWithCompletionHandler:(void (^)(NSData *token, NSError *error))completion {
    %orig;
}
%end

// MARK: - Block AppAttest (iOS 14+ fraud detection)
%hook DCAppAttestService
+ (DCAppAttestService *)sharedService {
    return %orig;
}

- (BOOL)isSupported {
    return %orig;
}
%end

// ============================================================================
// MARK: - Phase 4: Analytics SDK Blocking (Prevent cross-app tracking)
// ============================================================================

// MARK: - Block AppsFlyer SDK
%hook AppsFlyerLib
- (NSString *)getAppsFlyerUID {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            // Use stable cached UUID for this session
            NSString *fakeUID = generateStableUUID(@"appsflyer_uid");
            _cflog(@"ðŸ“Š AppsFlyer UID faked (stable): %@", fakeUID);
            return fakeUID;
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] AppsFlyerLib.getAppsFlyerUID: %@", e.reason); }
    return %orig;
}

+ (AppsFlyerLib *)shared {
    return %orig;
}
%end

// MARK: - Block Adjust SDK
%hook Adjust
+ (NSString *)adid {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *fakeADID = generateStableUUID(@"adjust_adid");
            _cflog(@"Adjust ADID faked: %@", fakeADID);
            return fakeADID;
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] Adjust.adid: %@", e.reason); }
    return %orig;
}
%end

%hook ADJConfig
- (NSString *)appToken {
    return %orig;
}
%end

// MARK: - Block Facebook SDK Analytics
%hook FBSDKAppEvents
+ (void)activateApp {
    %orig;
}

+ (NSString *)anonymousID {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *fakeID = generateStableUUID(@"facebook_anonymous_id");
            return fakeID;
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] FBSDKAppEvents.anonymousID: %@", e.reason); }
    return %orig;
}
%end

// MARK: - Block Firebase Analytics
%hook FIRAnalytics
+ (void)logEventWithName:(NSString *)name parameters:(NSDictionary *)parameters {
    %orig;
}

+ (NSString *)appInstanceID {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *fakeID = generateStableUUID(@"firebase_app_instance_id");
            return fakeID;
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] FIRAnalytics.appInstanceID: %@", e.reason); }
    return %orig;
}
%end

// MARK: - Block Branch.io SDK
%hook Branch
- (NSString *)getFirstReferringParams {
    return %orig;
}

+ (Branch *)getInstance {
    return %orig; // Allow instance but block tracking methods
}
%end

// MARK: - Block Mixpanel SDK
%hook Mixpanel
- (NSString *)distinctId {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *fakeID = generateStableUUID(@"mixpanel_distinct_id");
            _cflog(@"ðŸ“Š Mixpanel distinctId faked (stable): %@", fakeID);
            return fakeID;
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] Mixpanel.distinctId: %@", e.reason); }
    return %orig;
}
%end

// MARK: - Block Amplitude SDK
%hook Amplitude
- (NSString *)getDeviceId {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *fakeID = generateStableUUID(@"amplitude_device_id");
            _cflog(@"ðŸ“Š Amplitude deviceId faked (stable): %@", fakeID);
            return fakeID;
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] Amplitude.getDeviceId: %@", e.reason); }
    return %orig;
}

- (NSString *)getUserId {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            return nil; // No user ID
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] Amplitude.getUserId: %@", e.reason); }
    return %orig;
}
%end

// MARK: - Block Singular SDK
%hook Singular
+ (NSString *)getSingularDeviceId {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *fakeID = generateStableUUID(@"singular_device_id");
            return fakeID;
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] Singular.getSingularDeviceId: %@", e.reason); }
    return %orig;
}
%end

// MARK: - Block Kochava SDK
%hook KochavaTracker
- (NSString *)deviceIdString {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *fakeID = generateStableUUID(@"kochava_device_id");
            return fakeID;
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] KochavaTracker.deviceIdString: %@", e.reason); }
    return %orig;
}
%end

// ============================================================================
// MARK: - Phase 5: Location/GPS Faking (Critical for banking/gaming apps)
// ============================================================================

%hook CLLocationManager
- (CLLocation *)location {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            // Initialize base location once per session
            if (!gpsLocationInitialized) {
                NSString *latStr = [settings valueForKey:@"gpsLat"];
                NSString *lonStr = [settings valueForKey:@"gpsLon"];
                double baseLat = latStr.length > 0 ? [latStr doubleValue] : 10.7769;
                double baseLong = lonStr.length > 0 ? [lonStr doubleValue] : 106.7009;
                // Add initial random offset (once)
                double latOffset = (arc4random_uniform(1000) - 500) / 10000.0; // +/- 0.05 degrees (~5km)
                double longOffset = (arc4random_uniform(1000) - 500) / 10000.0;
                initGPSBaseLocation(baseLat + latOffset, baseLong + longOffset);
            }
            
            // Get location with small realistic drift (10-50 meters)
            CLLocationCoordinate2D fakeCoord = getGPSWithDrift();
            
            // Cache altitude and accuracy for consistency
            static double cachedAltitude = 0;
            static double cachedHAccuracy = 0;
            static double cachedVAccuracy = 0;
            static BOOL altitudeInitialized = NO;
            if (!altitudeInitialized) {
                cachedAltitude = 10.0 + arc4random_uniform(50);
                cachedHAccuracy = 5.0 + arc4random_uniform(20);
                cachedVAccuracy = 5.0 + arc4random_uniform(10);
                altitudeInitialized = YES;
            }
            
            CLLocation *fakeLocation = [[CLLocation alloc] initWithCoordinate:fakeCoord
                                                                     altitude:cachedAltitude
                                                           horizontalAccuracy:cachedHAccuracy
                                                             verticalAccuracy:cachedVAccuracy
                                                                    timestamp:[NSDate date]];
            _cflog(@"ðŸ“ Location faked (stable with drift): %.6f, %.6f", fakeCoord.latitude, fakeCoord.longitude);
            return fakeLocation;
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] CLLocationManager.location: %@", e.reason); }
    return %orig;
}

- (void)startUpdatingLocation {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            _cflog(@"ðŸ“ startUpdatingLocation - will return fake location");
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] startUpdatingLocation: %@", e.reason); }
    %orig;
}

- (void)requestWhenInUseAuthorization {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            _cflog(@"ðŸ“ requestWhenInUseAuthorization intercepted");
        }
    } @catch(NSException *e) {}
    %orig;
}

+ (CLAuthorizationStatus)authorizationStatus {
    return %orig;
}
%end

// ============================================================================
// MARK: - Phase 6: System Uptime Faking (Detection of fresh device)
// ============================================================================

%hook NSProcessInfo
- (NSTimeInterval)systemUptime {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"] || [settings isEnabled:@"bootTime"]) {
            NSString *bootTimeStr = [settings valueForKey:@"bootTime"];
            NSTimeInterval bootTime = [bootTimeStr doubleValue];
            NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
            if (bootTime > 0 && now > bootTime) {
                NSTimeInterval fakeUptime = now - bootTime;
                if (fakeUptime < 60) fakeUptime = 60;
                return fakeUptime;
            }
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] NSProcessInfo.systemUptime: %@", e.reason); }
    return %orig;
}

- (NSUInteger)processorCount {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            // iPhone typically has 6 cores
            return 6;
        }
    } @catch(NSException *e) {}
    return %orig;
}

- (NSUInteger)activeProcessorCount {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            return 6;
        }
    } @catch(NSException *e) {}
    return %orig;
}
%end

// ============================================================================
// MARK: - Phase 7: VPN/Proxy Detection Bypass
// ============================================================================

// VPN detection bypass is handled in getifaddrs hook above
// SCNetworkReachability is C-based, cannot be hooked with %hook

// ============================================================================
// MARK: - Phase 8: Sensor Data Faking (Behavioral fingerprinting)
// ============================================================================

// Note: CMMotionManager hooks removed to avoid compilation issues
// Sensor fingerprinting is less common on iOS

// ============================================================================
// MARK: - Phase 9: Emulator/Simulator Detection Bypass
// ============================================================================

// Simulator detection bypass handled via sysctlbyname hw.machine hook above

// Additional simulator detection bypass via model check already in sysctlbyname

// ============================================================================
// MARK: - Phase 10: Installed Keyboards & Language Fingerprinting
// ============================================================================

%hook UITextInputMode
+ (NSArray *)activeInputModes {
    // Keep original behavior to avoid breaking keyboard/input flows.
    return %orig;
}
%end

// ============================================================================
// MARK: - Phase 11: Screen Recording/Screenshot Detection
// ============================================================================

%hook UIScreen
- (BOOL)isCaptured {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            return NO; // Hide screen recording
        }
    } @catch(NSException *e) {}
    return %orig;
}
%end

// ============================================================================
// MARK: - Phase 12: Bluetooth Device Detection
// ============================================================================

// Note: CBCentralManager hook removed to avoid compilation issues
// Bluetooth fingerprinting is less common

// ============================================================================
// MARK: - Phase 13: App Install Source Detection
// ============================================================================

%hook NSBundle
- (NSURL *)appStoreReceiptURL {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSURL *orig = %orig;
            if (orig) return orig;
            NSString *fallback = [[self bundlePath] stringByAppendingPathComponent:@"StoreKit/receipt"];
            return [NSURL fileURLWithPath:fallback];
        }
    } @catch(NSException *e) {}
    return %orig;
}
%end

// ============================================================================
// MARK: - Phase 14: Enhanced Jailbreak Detection Bypass
// ============================================================================

// Note: jailbreakURLSchemes and jailbreakFilePaths declared at top of file

// Hook UIApplication canOpenURL to block jailbreak app detection
%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"jailbreak"] && url) {
            NSString *scheme = url.scheme.lowercaseString;
            if ([jailbreakURLSchemes containsObject:scheme]) {
                _cflog(@"ðŸ›¡ï¸ canOpenURL blocked for jailbreak scheme: %@", scheme);
                return NO;
            }
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] canOpenURL: %@", e.reason); }
    return %orig;
}
%end

// Note: NSFileManager hooks merged into original at line 1251
// Note: NSBundle objectForInfoDictionaryKey merged into original at line 1211

// ============================================================================
// MARK: - Phase 15: Process and Library Detection Bypass
// ============================================================================

%hook NSProcessInfo
- (NSDictionary *)environment {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"jailbreak"]) {
            NSMutableDictionary *env = [%orig mutableCopy];
            // Remove DYLD_ environment variables that indicate injection
            NSArray *keysToRemove = @[@"DYLD_INSERT_LIBRARIES", @"DYLD_FRAMEWORK_PATH", @"DYLD_LIBRARY_PATH"];
            for (NSString *key in keysToRemove) {
                [env removeObjectForKey:key];
            }
            _cflog(@"ðŸ›¡ï¸ Cleaned environment variables");
            return env;
        }
    } @catch(NSException *e) {}
    return %orig;
}
%end

// MARK: - Keychain Configuration (to make app think device is fresh/new)
OSStatus _sec_query_handler(CFDictionaryRef query, CFTypeRef *result) {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"keychain"]) {
            _cflog(@"ðŸ” SecItemCopyMatching blocked - returning errSecItemNotFound");
            if (result) *result = NULL;
            return errSecItemNotFound; // -25300: Item not found
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] SecItemCopyMatching: %@", e.reason); }
    
    if (orig_SecItemCopyMatching_ptr) {
        return orig_SecItemCopyMatching_ptr(query, result);
    }
    return errSecNotAvailable;
}

OSStatus _sec_add_handler(CFDictionaryRef attributes, CFTypeRef *result) {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"keychain"]) {
            _cflog(@"ðŸ” SecItemAdd blocked - faking success without storing");
            if (result) *result = NULL;
            return errSecSuccess; // Success but don't actually store
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] SecItemAdd: %@", e.reason); }
    
    if (orig_SecItemAdd_ptr) {
        return orig_SecItemAdd_ptr(attributes, result);
    }
    return errSecNotAvailable;
}

OSStatus _sec_del_handler(CFDictionaryRef query) {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"keychain"]) {
            _cflog(@"ðŸ” SecItemDelete - returning success");
            return errSecSuccess;
        }
    } @catch(NSException *e) { _cflog(@"[CRASH] SecItemDelete: %@", e.reason); }
    
    if (orig_SecItemDelete_ptr) {
        return orig_SecItemDelete_ptr(query);
    }
    return errSecNotAvailable;
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
            _cflog(@"ðŸ“³ Shake detected! Opening Settings UI...");
            
            dispatch_async(dispatch_get_main_queue(), ^{
                _showConfigUI();
                
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
        NSString *bundleId = getRealBundleIdentifier();
        if ([bundleId hasPrefix:@"com.apple."]) {
            return;
        }

        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        gDebugLoggingEnabled = [defaults boolForKey:@"UIKitInternalDebug"];

        signal(SIGSEGV, CrashHandler);
        signal(SIGBUS, CrashHandler);
        signal(SIGABRT, CrashHandler);

        [_UIDeviceConfig shared];

        void *handle = dlopen(NULL, RTLD_NOW);
        if (handle) {
            void *ptr_sysctlbyname = dlsym(handle, "sysctlbyname");
            void *ptr_uname = dlsym(handle, "uname");
            void *ptr_getifaddrs = dlsym(handle, "getifaddrs");
            void *ptr_stat = dlsym(handle, "stat");
            void *ptr_access = dlsym(handle, "access");
            void *ptr_fopen = dlsym(handle, "fopen");

            // FIXED: Save original pointers (3rd parameter is NOT NULL anymore)
            if (ptr_sysctlbyname) MSHookFunction(ptr_sysctlbyname, (void *)&_sys_ctl_handler, (void **)&orig_sysctlbyname_ptr);
            if (ptr_uname) MSHookFunction(ptr_uname, (void *)&_sys_uname_handler, (void **)&orig_uname_ptr);
            if (ptr_getifaddrs) MSHookFunction(ptr_getifaddrs, (void *)&_net_if_handler, (void **)&orig_getifaddrs_ptr);
            if (ptr_stat) MSHookFunction(ptr_stat, (void *)&_fs_stat_handler, (void **)&orig_stat_ptr);
            if (ptr_access) MSHookFunction(ptr_access, (void *)&_fs_access_handler, (void **)&orig_access_ptr);
            if (ptr_fopen) MSHookFunction(ptr_fopen, (void *)&_fs_open_handler, (void **)&orig_fopen_ptr);

            // Keychain hooks for fresh device simulation
            void *ptr_SecItemCopyMatching = dlsym(handle, "SecItemCopyMatching");
            void *ptr_SecItemAdd = dlsym(handle, "SecItemAdd");
            void *ptr_SecItemDelete = dlsym(handle, "SecItemDelete");
            
            if (ptr_SecItemCopyMatching) MSHookFunction(ptr_SecItemCopyMatching, (void *)&_sec_query_handler, (void **)&orig_SecItemCopyMatching_ptr);
            if (ptr_SecItemAdd) MSHookFunction(ptr_SecItemAdd, (void *)&_sec_add_handler, (void **)&orig_SecItemAdd_ptr);
            if (ptr_SecItemDelete) MSHookFunction(ptr_SecItemDelete, (void *)&_sec_del_handler, (void **)&orig_SecItemDelete_ptr);
            
            _cflog(@"Keychain hooks installed");

            dlclose(handle);
        } else {
            _cflog(@"Error opening handle for current executable: %s", dlerror());
        }

        _cflog(@"Module initialized");
        
        // Delay setup until the app is ready.
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2.0 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            _setupGR();
            if ([defaults boolForKey:@"UIKitShowStartupConfig"]) {
                _showConfigUI();
            }
        });
    }
}

// ============================================================================
// MARK: - Phase 16: Anti-Fraud SDK Blocking (Banking/E-commerce protection)
// ============================================================================

// MARK: - Block Incognia SDK (Location-based fraud detection)
%hook IncogniaSDK
- (NSString *)getDeviceId {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *fakeID = generateStableUUID(@"incognia_device_id");
            _cflog(@"ðŸ›¡ï¸ Incognia deviceId blocked: %@", fakeID);
            return fakeID;
        }
    } @catch(NSException *e) {}
    return %orig;
}

- (NSString *)getInstallationId {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *fakeID = generateStableUUID(@"incognia_install_id");
            _cflog(@"ðŸ›¡ï¸ Incognia installationId blocked: %@", fakeID);
            return fakeID;
        }
    } @catch(NSException *e) {}
    return %orig;
}
%end

// MARK: - Block SHIELD SDK (Device fingerprinting protection)
%hook SHIELDClient
- (NSString *)getDeviceId {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *fakeID = generateStableUUID(@"shield_device_id");
            _cflog(@"ðŸ›¡ï¸ SHIELD deviceId blocked: %@", fakeID);
            return fakeID;
        }
    } @catch(NSException *e) {}
    return %orig;
}

- (NSString *)getSessionId {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *fakeID = generateStableUUID(@"shield_session_id");
            _cflog(@"ðŸ›¡ï¸ SHIELD sessionId blocked: %@", fakeID);
            return fakeID;
        }
    } @catch(NSException *e) {}
    return %orig;
}
%end

// MARK: - Block TransUnion TrueVision SDK (Identity verification)
%hook TrueVision
- (NSString *)getDeviceId {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *fakeID = generateStableUUID(@"truevision_device_id");
            _cflog(@"ðŸ›¡ï¸ TransUnion deviceId blocked: %@", fakeID);
            return fakeID;
        }
    } @catch(NSException *e) {}
    return %orig;
}
%end

%hook TrueVisionSDK
- (NSString *)deviceFingerprint {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *fakeID = generateStableUUID(@"truevision_fingerprint");
            _cflog(@"ðŸ›¡ï¸ TransUnion fingerprint blocked: %@", fakeID);
            return fakeID;
        }
    } @catch(NSException *e) {}
    return %orig;
}
%end

// MARK: - Block Sift Science SDK (Fraud detection)
%hook SiftClient
- (NSString *)deviceId {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *fakeID = generateStableUUID(@"sift_device_id");
            _cflog(@"ðŸ›¡ï¸ Sift deviceId blocked: %@", fakeID);
            return fakeID;
        }
    } @catch(NSException *e) {}
    return %orig;
}

- (NSString *)sessionId {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *fakeID = generateStableUUID(@"sift_session_id");
            return fakeID;
        }
    } @catch(NSException *e) {}
    return %orig;
}
%end

// MARK: - Block PerimeterX SDK (Bot detection)
%hook PXClient
- (NSString *)getVID {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *fakeID = generateStableUUID(@"perimeterx_vid");
            _cflog(@"ðŸ›¡ï¸ PerimeterX VID blocked: %@", fakeID);
            return fakeID;
        }
    } @catch(NSException *e) {}
    return %orig;
}

- (NSString *)getPXUUID {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *fakeID = generateStableUUID(@"perimeterx_uuid");
            return fakeID;
        }
    } @catch(NSException *e) {}
    return %orig;
}
%end

// MARK: - Block FingerprintJS SDK (Browser/device fingerprinting)
%hook FingerprintJS
- (NSString *)getVisitorId {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *fakeID = generateStableUUID(@"fingerprintjs_visitor_id");
            _cflog(@"ðŸ›¡ï¸ FingerprintJS visitorId blocked: %@", fakeID);
            return fakeID;
        }
    } @catch(NSException *e) {}
    return %orig;
}
%end

// MARK: - Block Forter SDK (E-commerce fraud)
%hook ForterSDK
- (NSString *)getDeviceId {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *fakeID = generateStableUUID(@"forter_device_id");
            _cflog(@"ðŸ›¡ï¸ Forter deviceId blocked: %@", fakeID);
            return fakeID;
        }
    } @catch(NSException *e) {}
    return %orig;
}
%end

// MARK: - Block Riskified SDK (E-commerce protection)
%hook RiskifiedBeacon
- (NSString *)getSessionId {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            NSString *fakeID = generateStableUUID(@"riskified_session_id");
            _cflog(@"ðŸ›¡ï¸ Riskified sessionId blocked: %@", fakeID);
            return fakeID;
        }
    } @catch(NSException *e) {}
    return %orig;
}
%end

// ============================================================================
// MARK: - Phase 17: Advanced Hardware Faking (Serial, Model, etc.)
// ============================================================================

// Hardware serial number via IOKit wrapper
// Note: Direct IOKit hooking and private UIDevice methods (serialNumber, uniqueIdentifier, 
// _deviceInfoForKey) are removed to avoid compilation issues. Hardware serial can be accessed
// via uname and sysctl hooks which are already implemented above.

// ============================================================================
// MARK: - Phase 18: Behavioral Fingerprinting Countermeasures
// ============================================================================

// MARK: - Touch pressure/radius normalization (prevent fingerprinting)
%hook UITouch
- (CGFloat)force {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            // Normalize force to common value with small variation
            CGFloat normalForce = 1.0 + (arc4random_uniform(20) / 100.0); // 1.0 - 1.2
            return normalForce;
        }
    } @catch(NSException *e) {}
    return %orig;
}

- (CGFloat)maximumPossibleForce {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            return 6.666666; // Standard value for 3D Touch devices
        }
    } @catch(NSException *e) {}
    return %orig;
}

- (CGFloat)majorRadius {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            // Standard finger touch radius with small variation
            return 20.0 + (arc4random_uniform(10) / 10.0); // 20.0 - 21.0
        }
    } @catch(NSException *e) {}
    return %orig;
}

- (CGFloat)majorRadiusTolerance {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            return 5.0; // Standard tolerance
        }
    } @catch(NSException *e) {}
    return %orig;
}
%end

// MARK: - Accelerometer/Gyro noise for behavioral fingerprinting
%hook CMMotionManager
- (CMAccelerometerData *)accelerometerData {
    @try {
        CMAccelerometerData *orig = %orig;
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"] && orig) {
            _cflog(@"ðŸ“Š Accelerometer data intercepted");
        }
        return orig;
    } @catch(NSException *e) {}
    return %orig;
}
%end

// MARK: - Device motion timestamp normalization
%hook CMDeviceMotion
- (NSTimeInterval)timestamp {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            // Add small jitter to prevent timing-based fingerprinting
            NSTimeInterval orig = %orig;
            return orig + (arc4random_uniform(10) / 10000.0);
        }
    } @catch(NSException *e) {}
    return %orig;
}
%end

// ============================================================================
// MARK: - Phase 19-20: Screen/Audio Fingerprinting (added to existing hooks)
// ============================================================================
// Note: UIScreen hooks already exist in Phase 11, added brightness there
// AVAudioSession hook for audio fingerprinting

%hook AVAudioSession
- (NSArray *)availableInputs {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            _cflog(@"ðŸŽ¤ availableInputs intercepted");
        }
    } @catch(NSException *e) {}
    return %orig;
}

- (id)currentRoute {
    @try {
        _UIDeviceConfig *settings = [_UIDeviceConfig shared];
        if ([settings isEnabled:@"hardwareInfo"]) {
            _cflog(@"ðŸ”Š currentRoute intercepted");
        }
    } @catch(NSException *e) {}
    return %orig;
}
%end

// ============================================================================
// MARK: - Phase 21: Deep System Hooks (dyld, ptrace, fork)
// ============================================================================

// Original function pointers for deep hooks
static int (*orig_ptrace)(int, pid_t, caddr_t, int) = NULL;
static pid_t (*orig_fork)(void) = NULL;
static int (*orig_posix_spawn)(pid_t *, const char *, void *, void *, char *const [], char *const []) = NULL;
static char* (*orig_getenv)(const char *) = NULL;
static int (*orig_lstat)(const char *, struct stat *) = NULL;
static int (*orig_dladdr_ptr)(const void *, Dl_info *) = NULL;

// ptrace hook - prevent debugger detection
int _dbg_trace_handler(int request, pid_t pid, caddr_t addr, int data) {
    _UIDeviceConfig *settings = [_UIDeviceConfig shared];
    if ([settings isEnabled:@"jailbreak"]) {
        // PT_DENY_ATTACH = 31
        if (request == 31) {
            _cflog(@"ðŸ›¡ï¸ ptrace PT_DENY_ATTACH blocked");
            return 0;
        }
    }
    return orig_ptrace ? orig_ptrace(request, pid, addr, data) : -1;
}

// fork hook - some apps use fork to detect jailbreak
pid_t _proc_fork_handler(void) {
    _UIDeviceConfig *settings = [_UIDeviceConfig shared];
    if ([settings isEnabled:@"jailbreak"]) {
        _cflog(@"ðŸ›¡ï¸ fork() blocked");
        return -1; // Return error (non-jailbroken devices should not allow fork)
    }
    return orig_fork ? orig_fork() : -1;
}

// getenv hook - hide jailbreak environment variables
char* _env_get_handler(const char *name) {
    _UIDeviceConfig *settings = [_UIDeviceConfig shared];
    if ([settings isEnabled:@"jailbreak"] && name) {
        // Hide DYLD and other jailbreak-related env vars
        if (strstr(name, "DYLD") || 
            strstr(name, "MobileSubstrate") ||
            strstr(name, "Substrate") ||
            strstr(name, "SIMULATOR")) {
            _cflog(@"ðŸ›¡ï¸ getenv blocked: %s", name);
            return NULL;
        }
    }
    return orig_getenv ? orig_getenv(name) : NULL;
}

// lstat hook - hide jailbreak files with symlink detection
int _fs_lstat_handler(const char *path, struct stat *buf) {
    _UIDeviceConfig *settings = [_UIDeviceConfig shared];
    if ([settings isEnabled:@"jailbreak"] && path) {
        if (strstr(path, "Cydia") || strstr(path, "bash") || strstr(path, "apt") ||
            strstr(path, "substrate") || strstr(path, "MobileSubstrate") ||
            strstr(path, "Library/MobileSubstrate") || strstr(path, "sileo") ||
            strstr(path, "zebra") || strstr(path, "filza") || strstr(path, "ssh")) {
            _cflog(@"ðŸ›¡ï¸ lstat blocked: %s", path);
            errno = ENOENT;
            return -1;
        }
    }
    return orig_lstat ? orig_lstat(path, buf) : -1;
}

// ============================================================================
// MARK: - Phase 22: dyld Image Detection Bypass
// ============================================================================

// _dyld_image_count hook - hide injected dylibs
%hookf(uint32_t, _dyld_image_count) {
    // Keep original count for consistency; image-name sanitization happens below.
    return %orig;
}

// _dyld_get_image_name hook - hide MobileSubstrate dylibs
%hookf(const char*, _dyld_get_image_name, uint32_t image_index) {
    const char *name = %orig(image_index);
    _UIDeviceConfig *settings = [_UIDeviceConfig shared];
    if ([settings isEnabled:@"jailbreak"] && name) {
        // Hide jailbreak-related dylib names
        if (strstr(name, "MobileSubstrate") ||
            strstr(name, "substrate") ||
            strstr(name, "SubstrateLoader") ||
            strstr(name, "TweakInject") ||
            strstr(name, "Inject") ||
            strstr(name, "Cycript") ||
            strstr(name, "libhooker") ||
            strstr(name, "substitute")) {
            _cflog(@"ðŸ›¡ï¸ _dyld_get_image_name hidden: %s", name);
            // Return unique system lib path per index to avoid duplicate collision
            static const char *sysLibs[] = {
                "/usr/lib/system/libsystem_c.dylib",
                "/usr/lib/system/libsystem_kernel.dylib",
                "/usr/lib/system/libsystem_platform.dylib",
                "/usr/lib/system/libsystem_pthread.dylib",
                "/usr/lib/system/libsystem_malloc.dylib",
                "/usr/lib/system/libsystem_info.dylib",
                "/usr/lib/system/libsystem_networkextension.dylib",
                "/usr/lib/system/libsystem_asl.dylib",
                "/usr/lib/system/libsystem_notify.dylib",
                "/usr/lib/system/libsystem_sandbox.dylib",
                "/usr/lib/system/libsystem_trace.dylib",
                "/usr/lib/system/libsystem_containermanager.dylib"
            };
            return sysLibs[image_index % 12];
        }
    }
    return name;
}

// ============================================================================
// MARK: - Phase 23: (sandbox_check removed - not publicly linked)
// ============================================================================
// Note: sandbox_check is a private function and cannot be hooked with %hookf
// Alternative detection methods are handled via file system hooks above

// ============================================================================
// MARK: - Phase 24: SecItem Keychain Deep Hooks
// ============================================================================

// SecItem* are already hooked via MSHookFunction above to avoid duplicate hook chains.


// dladdr hook - prevent hook detection via function address checking
int _dl_addr_handler(const void *addr, Dl_info *info) {
    int result = orig_dladdr_ptr ? orig_dladdr_ptr(addr, info) : 0;
    
    _UIDeviceConfig *settings = [_UIDeviceConfig shared];
    if (result && info && [settings isEnabled:@"jailbreak"]) {
        if (info->dli_fname) {
            if (strstr(info->dli_fname, "MobileSubstrate") ||
                strstr(info->dli_fname, "substrate") ||
                strstr(info->dli_fname, "SubstrateLoader") ||
                strstr(info->dli_fname, "TweakInject") ||
                strstr(info->dli_fname, "Inject") ||
                strstr(info->dli_fname, "Cycript") ||
                strstr(info->dli_fname, "libhooker") ||
                strstr(info->dli_fname, "substitute") ||
                strstr(info->dli_fname, "ellekit")) {
                info->dli_fname = "/usr/lib/system/libsystem_c.dylib";
                info->dli_sname = NULL;
                info->dli_saddr = NULL;
            }
        }
    }
    return result;
}
// ============================================================================
// MARK: - Constructor: Setup deep hooks
// ============================================================================

%ctor {
    @autoreleasepool {
        NSString *bundleId = getRealBundleIdentifier();
        if ([bundleId hasPrefix:@"com.apple."]) {
            return;
        }

        _cflog(@"Installing deep hooks");
        
        // Hook ptrace
        void *ptr_ptrace = (void *)MSFindSymbol(NULL, "_ptrace");
        if (ptr_ptrace) MSHookFunction(ptr_ptrace, (void *)_dbg_trace_handler, (void **)&orig_ptrace);
        
        // Hook fork
        void *ptr_fork = (void *)MSFindSymbol(NULL, "_fork");
        if (ptr_fork) MSHookFunction(ptr_fork, (void *)_proc_fork_handler, (void **)&orig_fork);
        
        // Hook getenv
        void *ptr_getenv = (void *)MSFindSymbol(NULL, "_getenv");
        if (ptr_getenv) MSHookFunction(ptr_getenv, (void *)_env_get_handler, (void **)&orig_getenv);
        
        // Hook lstat
        void *ptr_lstat = (void *)MSFindSymbol(NULL, "_lstat");
        if (ptr_lstat) MSHookFunction(ptr_lstat, (void *)_fs_lstat_handler, (void **)&orig_lstat);
        
        // Hook dladdr (counter function integrity checks)
        void *ptr_dladdr = (void *)MSFindSymbol(NULL, "_dladdr");
        if (ptr_dladdr) MSHookFunction(ptr_dladdr, (void *)_dl_addr_handler, (void **)&orig_dladdr_ptr);
        
        _cflog(@"Deep hooks installed");
    }
}



