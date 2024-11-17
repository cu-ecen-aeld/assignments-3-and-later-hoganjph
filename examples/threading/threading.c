#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
//#define DEBUG_LOG(msg,...)
#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{
    struct thread_data* threadfunc_args = (struct thread_data *) thread_param;
    int rc = usleep(1000 * threadfunc_args->wait_to_obtain_ms);
    if (rc != 0) {
        ERROR_LOG("usleep failed with %d", rc);
        threadfunc_args->thread_complete_success = false;
        return thread_param;
    }

    rc = pthread_mutex_lock(threadfunc_args->mutex);
    if (rc != 0) {
        ERROR_LOG("pthread_mutex_lock failed with %d", rc);
        threadfunc_args->thread_complete_success = false;
        return thread_param;
    }

    rc = usleep(1000 * threadfunc_args->wait_to_release_ms);
    if (rc != 0) {
        ERROR_LOG("usleep failed with %d", rc);
        threadfunc_args->thread_complete_success = false;
        return thread_param;
    }

    rc = pthread_mutex_unlock(threadfunc_args->mutex);
    if (rc != 0) {
        ERROR_LOG("pthread_mutex_unlock failed with %d", rc);
        threadfunc_args->thread_complete_success = false;
        return thread_param;
    }

    threadfunc_args->thread_complete_success = true;
    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    struct thread_data* td = malloc(sizeof(struct thread_data));
    td->wait_to_obtain_ms = wait_to_obtain_ms;
    td->wait_to_release_ms = wait_to_release_ms;
    td->thread_complete_success = false;
    td->mutex = mutex;

    int rc = pthread_create(thread, NULL, threadfunc, (void*)td);
    if (rc != 0) {
        ERROR_LOG("pthread_create failed with %d", rc);
        return false;
    }

    return true;
}

