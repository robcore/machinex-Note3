#define KERN_RESTART_CODE	(KERN_SIGRETURN_CODE + sizeof(sigreturn_codes))

extern const unsigned long sigreturn_codes[7];
extern const unsigned long syscall_restart_code[2];
