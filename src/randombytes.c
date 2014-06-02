/*
 * randombytes() is required by Tweetnacl.
 */

#include <stdlib.h>

void randombytes(u8 *dst, u64 len)
{
    int ret;

    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();

    ret = _PyOS_URandom(dst, len);
    
    PyGILState_Release(gstate);

    /* Bad way to handle an error, but Tweetnacl does not expect randombytes()
     * to fail. The only thin we could potentially do here is to longjmp()
     * back to Python and re-raise the exception there. For now, just exit().
     */

    if (ret < 0) {
        fprintf(stderr, "_PyOS_URandom failed()\n");
        exit(1);
    }
}
