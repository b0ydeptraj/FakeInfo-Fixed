const fs = require('fs');
const text = fs.readFileSync('Tweak.xm', 'utf8');
const hooks = text.split('%hook');
for(let i=1; i<hooks.length; i++) {
    const block = hooks[i].split('%end')[0];
    const lines = block.split('\n');
    let insideMethod = false;
    let methodLines = [];
    let methodSignature = '';

    for (const line of lines) {
        if (line.match(/^[+-]\s*\(/)) {
            insideMethod = true;
            methodLines = [];
            methodSignature = line.trim();
        }
        
        if (insideMethod) {
            methodLines.push(line);
            if (line.trim() === '}' || (line.includes('}') && !line.includes('{'))) {
                // Approximate end of method
                const methodBody = methodLines.join('\n');
                if (!methodBody.includes('SC_PREVENT_LOOP')) {
                    console.log('MISSING IN HOOK: ' + methodSignature);
                }
                insideMethod = false;
            }
        }
    }
}
