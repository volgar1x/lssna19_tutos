#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <seccomp.h>

void call_child(void) {
  scmp_filter_ctx ctx;
  int rc;

  ctx = seccomp_init(SCMP_ACT_KILL); // whitelist
  //ctx = seccomp_init(SCMP_ACT_ALLOW); // blacklist
  
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
      SCMP_A0(SCMP_CMP_EQ, STDOUT_FILENO));
  if (rc < 0) {
    printf("scmp rule add failed %d\n", rc);
    goto out;
  }
  
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  if (rc < 0) {
    printf("scmp rule add failed %d\n", rc);
    goto out;
  }
  
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
  if (rc < 0) {
    printf("scmp rule add failed %d\n", rc);
    goto out;
  }

  rc = seccomp_load(ctx);
  if (rc < 0) {
    printf("scmp load failed %d\n", rc);
    goto out;
  }

out:
  seccomp_release(ctx);
}

int main(void) {
  pid_t cpid;

  printf("main\n");

  cpid = fork();
  if (cpid < 0) {
    printf("fork failed\n");
    exit(-1);
  }

  if (cpid == 0) {
    call_child();
    printf("child stdout\n");
    fprintf(stderr, "child stderr\n");
  } else {
    int ret;
    printf("parent\n");
    wait(&ret);
    printf("child returned %d\n", ret);
  }

  return 0;
}
