#ifndef SENTINEL_REMEDIATION_H
#define SENTINEL_REMEDIATION_H

/* Preview of the sysctl profile that would be written. Caller frees. */
char *remediation_conf_preview(void);

/* Plan/apply the kernel hardening profile. When dry_run != 0 nothing is
 * modified. Returns the number of settings actually written, or -1 on error. */
int remediation_apply(int dry_run);

#endif /* SENTINEL_REMEDIATION_H */
