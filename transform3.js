const fs = require('fs');
let t = fs.readFileSync('Tweak.xm', 'utf8');

const newPthreadSetup = `
#include <pthread.h>

static pthread_key_t _sc_depth_key;
static pthread_once_t _sc_key_once = PTHREAD_ONCE_INIT;

static void _sc_make_key() {
    pthread_key_create(&_sc_depth_key, NULL);
}

static inline int _get_sc_depth() {
    pthread_once(&_sc_key_once, _sc_make_key);
    return (int)(long)pthread_getspecific(_sc_depth_key);
}

static inline void _set_sc_depth(int depth) {
    pthread_once(&_sc_key_once, _sc_make_key);
    pthread_setspecific(_sc_depth_key, (void *)(long)depth);
}

static inline void _sc_hook_leave_cleanup(int *unused) {
    int depth = _get_sc_depth();
    if (depth > 0) {
        _set_sc_depth(depth - 1);
    }
}
`;

// Remove old pthread setup
t = t.replace(/#include <pthread\.h>[\s\S]*?_set_sc_depth\(depth - 1\);\n    }\n}/, newPthreadSetup);

fs.writeFileSync('Tweak.xm', t);
console.log('Done!');
