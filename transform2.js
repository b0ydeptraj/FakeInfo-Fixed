const fs = require('fs');
let t = fs.readFileSync('Tweak.xm', 'utf8');

const pthreadSetup = `
#include <pthread.h>

static pthread_key_t _sc_depth_key;

__attribute__((constructor))
static void _sc_init_key() {
    pthread_key_create(&_sc_depth_key, NULL);
}

static inline int _get_sc_depth() {
    return (int)(long)pthread_getspecific(_sc_depth_key);
}

static inline void _set_sc_depth(int depth) {
    pthread_setspecific(_sc_depth_key, (void *)(long)depth);
}

static inline void _sc_hook_leave_cleanup(int *unused) {
    int depth = _get_sc_depth();
    if (depth > 0) {
        _set_sc_depth(depth - 1);
    }
}
`;

t = t.replace(/static __thread int _scHookDepth = 0;\n\nstatic inline void _sc_hook_leave_cleanup\(int \*unused\) {\n    _scHookDepth--;\n}/, pthreadSetup);

t = t.replace(/_scHookDepth > 0/g, '_get_sc_depth() > 0');
t = t.replace(/_scHookDepth > 5/g, '_get_sc_depth() > 5');
t = t.replace(/_scHookDepth\+\+;/g, '_set_sc_depth(_get_sc_depth() + 1);');

fs.writeFileSync('Tweak.xm', t);
console.log('Done!');
