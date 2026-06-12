const fs = require('fs');
let code = fs.readFileSync('Tweak.xm', 'utf8');

const hookRegex = /(-|\+)\s*\(\s*([^)]+)\s*\)\s*([^{]+)\s*\{\s*SC_PREVENT_LOOP\([^)]*\);/g;

code = code.replace(hookRegex, (match, sign, returnType, methodName) => {
    // Check if there is already an SC_IS_REENTRANT check right after
    let index = code.indexOf(match);
    let nextChars = code.substring(index, index + match.length + 150);
    if (nextChars.includes('if (SC_IS_REENTRANT)')) {
        return match;
    }

    let retType = returnType.trim();
    let fallback = '';

    if (retType === 'void') {
        fallback = 'return;';
    } else if (retType.includes('*') || retType === 'id' || retType.includes('NSArray') || retType.includes('NSString') || retType.includes('NSDictionary')) {
        fallback = 'return nil;';
    } else if (retType === 'BOOL' || retType === 'bool') {
        fallback = 'return NO;';
    } else if (retType === 'CGRect') {
        fallback = 'return CGRectZero;';
    } else if (retType === 'CGSize') {
        fallback = 'return CGSizeZero;';
    } else if (retType === 'CGPoint') {
        fallback = 'return CGPointZero;';
    } else if (retType === 'UIDeviceBatteryState') {
        fallback = 'return UIDeviceBatteryStateUnknown;';
    } else {
        fallback = 'return 0;';
    }

    return match + '\n    if (SC_IS_REENTRANT) ' + fallback + ' // Auto-fallback';
});

fs.writeFileSync('Tweak.xm', code);
console.log('Fixed SC_IS_REENTRANT fallbacks!');
