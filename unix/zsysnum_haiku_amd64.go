// go run mksysnum.go /boot/home/code/haiku/generated/objects/haiku/x86_64/common/system/libroot/os/syscalls.S.inc
// Code generated by the command above; see README.md. DO NOT EDIT.

//go:build amd64 && haiku
// +build amd64,haiku

package unix

const (
	SYS_IS_COMPUTER_ON                   = 0
	SYS_GENERIC_SYSCALL                  = 1
	SYS_GETRLIMIT                        = 2
	SYS_SETRLIMIT                        = 3
	SYS_SHUTDOWN                         = 4
	SYS_GET_SAFEMODE_OPTION              = 5
	SYS_WAIT_FOR_OBJECTS                 = 6
	SYS_MUTEX_LOCK                       = 7
	SYS_MUTEX_UNLOCK                     = 8
	SYS_MUTEX_SWITCH_LOCK                = 9
	SYS_MUTEX_SEM_ACQUIRE                = 10
	SYS_MUTEX_SEM_RELEASE                = 11
	SYS_CREATE_SEM                       = 12
	SYS_DELETE_SEM                       = 13
	SYS_SWITCH_SEM                       = 14
	SYS_SWITCH_SEM_ETC                   = 15
	SYS_ACQUIRE_SEM                      = 16
	SYS_ACQUIRE_SEM_ETC                  = 17
	SYS_RELEASE_SEM                      = 18
	SYS_RELEASE_SEM_ETC                  = 19
	SYS_GET_SEM_COUNT                    = 20
	SYS_GET_SEM_INFO                     = 21
	SYS_GET_NEXT_SEM_INFO                = 22
	SYS_SET_SEM_OWNER                    = 23
	SYS_REALTIME_SEM_OPEN                = 24
	SYS_REALTIME_SEM_CLOSE               = 25
	SYS_REALTIME_SEM_UNLINK              = 26
	SYS_REALTIME_SEM_GET_VALUE           = 27
	SYS_REALTIME_SEM_POST                = 28
	SYS_REALTIME_SEM_WAIT                = 29
	SYS_XSI_SEMGET                       = 30
	SYS_XSI_SEMCTL                       = 31
	SYS_XSI_SEMOP                        = 32
	SYS_XSI_MSGCTL                       = 33
	SYS_XSI_MSGGET                       = 34
	SYS_XSI_MSGRCV                       = 35
	SYS_XSI_MSGSND                       = 36
	SYS_LOAD_IMAGE                       = 37
	SYS_EXIT_TEAM                        = 38
	SYS_KILL_TEAM                        = 39
	SYS_GET_CURRENT_TEAM                 = 40
	SYS_WAIT_FOR_TEAM                    = 41
	SYS_WAIT_FOR_CHILD                   = 42
	SYS_EXEC                             = 43
	SYS_FORK                             = 44
	SYS_PROCESS_INFO                     = 45
	SYS_SETPGID                          = 46
	SYS_SETSID                           = 47
	SYS_CHANGE_ROOT                      = 48
	SYS_SPAWN_THREAD                     = 49
	SYS_FIND_THREAD                      = 50
	SYS_SUSPEND_THREAD                   = 51
	SYS_RESUME_THREAD                    = 52
	SYS_RENAME_THREAD                    = 53
	SYS_SET_THREAD_PRIORITY              = 54
	SYS_KILL_THREAD                      = 55
	SYS_EXIT_THREAD                      = 56
	SYS_CANCEL_THREAD                    = 57
	SYS_THREAD_YIELD                     = 58
	SYS_WAIT_FOR_THREAD                  = 59
	SYS_WAIT_FOR_THREAD_ETC              = 60
	SYS_HAS_DATA                         = 61
	SYS_SEND_DATA                        = 62
	SYS_RECEIVE_DATA                     = 63
	SYS_RESTORE_SIGNAL_FRAME             = 64
	SYS_GET_THREAD_INFO                  = 65
	SYS_GET_NEXT_THREAD_INFO             = 66
	SYS_GET_TEAM_INFO                    = 67
	SYS_GET_NEXT_TEAM_INFO               = 68
	SYS_GET_TEAM_USAGE_INFO              = 69
	SYS_GET_EXTENDED_TEAM_INFO           = 70
	SYS_START_WATCHING_SYSTEM            = 71
	SYS_STOP_WATCHING_SYSTEM             = 72
	SYS_BLOCK_THREAD                     = 73
	SYS_UNBLOCK_THREAD                   = 74
	SYS_UNBLOCK_THREADS                  = 75
	SYS_ESTIMATE_MAX_SCHEDULING_LATENCY  = 76
	SYS_SET_SCHEDULER_MODE               = 77
	SYS_GET_SCHEDULER_MODE               = 78
	SYS_GETGID                           = 79
	SYS_GETUID                           = 80
	SYS_SETREGID                         = 81
	SYS_SETREUID                         = 82
	SYS_GETGROUPS                        = 83
	SYS_SETGROUPS                        = 84
	SYS_SEND_SIGNAL                      = 85
	SYS_SET_SIGNAL_MASK                  = 86
	SYS_SIGACTION                        = 87
	SYS_SIGWAIT                          = 88
	SYS_SIGSUSPEND                       = 89
	SYS_SIGPENDING                       = 90
	SYS_SET_SIGNAL_STACK                 = 91
	SYS_REGISTER_IMAGE                   = 92
	SYS_UNREGISTER_IMAGE                 = 93
	SYS_IMAGE_RELOCATED                  = 94
	SYS_LOADING_APP_FAILED               = 95
	SYS_GET_IMAGE_INFO                   = 96
	SYS_GET_NEXT_IMAGE_INFO              = 97
	SYS_READ_KERNEL_IMAGE_SYMBOLS        = 98
	SYS_MOUNT                            = 99
	SYS_UNMOUNT                          = 100
	SYS_READ_FS_INFO                     = 101
	SYS_WRITE_FS_INFO                    = 102
	SYS_NEXT_DEVICE                      = 103
	SYS_SYNC                             = 104
	SYS_ENTRY_REF_TO_PATH                = 105
	SYS_NORMALIZE_PATH                   = 106
	SYS_OPEN_ENTRY_REF                   = 107
	SYS_OPEN                             = 108
	SYS_OPEN_DIR_ENTRY_REF               = 109
	SYS_OPEN_DIR                         = 110
	SYS_OPEN_PARENT_DIR                  = 111
	SYS_FCNTL                            = 112
	SYS_FSYNC                            = 113
	SYS_FLOCK                            = 114
	SYS_SEEK                             = 115
	SYS_CREATE_DIR_ENTRY_REF             = 116
	SYS_CREATE_DIR                       = 117
	SYS_REMOVE_DIR                       = 118
	SYS_READ_LINK                        = 119
	SYS_CREATE_SYMLINK                   = 120
	SYS_CREATE_LINK                      = 121
	SYS_UNLINK                           = 122
	SYS_RENAME                           = 123
	SYS_CREATE_FIFO                      = 124
	SYS_CREATE_PIPE                      = 125
	SYS_ACCESS                           = 126
	SYS_SELECT                           = 127
	SYS_POLL                             = 128
	SYS_OPEN_ATTR_DIR                    = 129
	SYS_READ_ATTR                        = 130
	SYS_WRITE_ATTR                       = 131
	SYS_STAT_ATTR                        = 132
	SYS_OPEN_ATTR                        = 133
	SYS_REMOVE_ATTR                      = 134
	SYS_RENAME_ATTR                      = 135
	SYS_OPEN_INDEX_DIR                   = 136
	SYS_CREATE_INDEX                     = 137
	SYS_READ_INDEX_STAT                  = 138
	SYS_REMOVE_INDEX                     = 139
	SYS_GETCWD                           = 140
	SYS_SETCWD                           = 141
	SYS_OPEN_QUERY                       = 142
	SYS_READ                             = 143
	SYS_READV                            = 144
	SYS_WRITE                            = 145
	SYS_WRITEV                           = 146
	SYS_IOCTL                            = 147
	SYS_READ_DIR                         = 148
	SYS_REWIND_DIR                       = 149
	SYS_READ_STAT                        = 150
	SYS_WRITE_STAT                       = 151
	SYS_CLOSE                            = 152
	SYS_DUP                              = 153
	SYS_DUP2                             = 154
	SYS_LOCK_NODE                        = 155
	SYS_UNLOCK_NODE                      = 156
	SYS_GET_NEXT_FD_INFO                 = 157
	SYS_PREALLOCATE                      = 158
	SYS_SOCKET                           = 159
	SYS_BIND                             = 160
	SYS_SHUTDOWN_SOCKET                  = 161
	SYS_CONNECT                          = 162
	SYS_LISTEN                           = 163
	SYS_ACCEPT                           = 164
	SYS_RECV                             = 165
	SYS_RECVFROM                         = 166
	SYS_RECVMSG                          = 167
	SYS_SEND                             = 168
	SYS_SENDTO                           = 169
	SYS_SENDMSG                          = 170
	SYS_GETSOCKOPT                       = 171
	SYS_SETSOCKOPT                       = 172
	SYS_GETPEERNAME                      = 173
	SYS_GETSOCKNAME                      = 174
	SYS_SOCKATMARK                       = 175
	SYS_SOCKETPAIR                       = 176
	SYS_GET_NEXT_SOCKET_STAT             = 177
	SYS_STOP_NOTIFYING                   = 178
	SYS_START_WATCHING                   = 179
	SYS_STOP_WATCHING                    = 180
	SYS_SET_REAL_TIME_CLOCK              = 181
	SYS_SET_TIMEZONE                     = 182
	SYS_GET_TIMEZONE                     = 183
	SYS_SET_REAL_TIME_CLOCK_IS_GMT       = 184
	SYS_GET_REAL_TIME_CLOCK_IS_GMT       = 185
	SYS_GET_CLOCK                        = 186
	SYS_SET_CLOCK                        = 187
	SYS_SYSTEM_TIME                      = 188
	SYS_SNOOZE_ETC                       = 189
	SYS_CREATE_TIMER                     = 190
	SYS_DELETE_TIMER                     = 191
	SYS_GET_TIMER                        = 192
	SYS_SET_TIMER                        = 193
	SYS_CREATE_AREA                      = 194
	SYS_DELETE_AREA                      = 195
	SYS_AREA_FOR                         = 196
	SYS_FIND_AREA                        = 197
	SYS_GET_AREA_INFO                    = 198
	SYS_GET_NEXT_AREA_INFO               = 199
	SYS_RESIZE_AREA                      = 200
	SYS_TRANSFER_AREA                    = 201
	SYS_SET_AREA_PROTECTION              = 202
	SYS_CLONE_AREA                       = 203
	SYS_RESERVE_ADDRESS_RANGE            = 204
	SYS_UNRESERVE_ADDRESS_RANGE          = 205
	SYS_MAP_FILE                         = 206
	SYS_UNMAP_MEMORY                     = 207
	SYS_SET_MEMORY_PROTECTION            = 208
	SYS_SYNC_MEMORY                      = 209
	SYS_MEMORY_ADVICE                    = 210
	SYS_GET_MEMORY_PROPERTIES            = 211
	SYS_MLOCK                            = 212
	SYS_MUNLOCK                          = 213
	SYS_CREATE_PORT                      = 214
	SYS_CLOSE_PORT                       = 215
	SYS_DELETE_PORT                      = 216
	SYS_FIND_PORT                        = 217
	SYS_GET_PORT_INFO                    = 218
	SYS_GET_NEXT_PORT_INFO               = 219
	SYS_PORT_BUFFER_SIZE_ETC             = 220
	SYS_PORT_COUNT                       = 221
	SYS_READ_PORT_ETC                    = 222
	SYS_SET_PORT_OWNER                   = 223
	SYS_WRITE_PORT_ETC                   = 224
	SYS_WRITEV_PORT_ETC                  = 225
	SYS_GET_PORT_MESSAGE_INFO_ETC        = 226
	SYS_KERNEL_DEBUGGER                  = 227
	SYS_REGISTER_SYSLOG_DAEMON           = 228
	SYS_DEBUGGER                         = 229
	SYS_DISABLE_DEBUGGER                 = 230
	SYS_INSTALL_DEFAULT_DEBUGGER         = 231
	SYS_INSTALL_TEAM_DEBUGGER            = 232
	SYS_REMOVE_TEAM_DEBUGGER             = 233
	SYS_DEBUG_THREAD                     = 234
	SYS_WAIT_FOR_DEBUGGER                = 235
	SYS_SET_DEBUGGER_BREAKPOINT          = 236
	SYS_CLEAR_DEBUGGER_BREAKPOINT        = 237
	SYS_SYSTEM_PROFILER_START            = 238
	SYS_SYSTEM_PROFILER_NEXT_BUFFER      = 239
	SYS_SYSTEM_PROFILER_STOP             = 240
	SYS_SYSTEM_PROFILER_RECORDED         = 241
	SYS_GET_SYSTEM_INFO                  = 242
	SYS_GET_CPU_INFO                     = 243
	SYS_GET_CPU_TOPOLOGY_INFO            = 244
	SYS_ANALYZE_SCHEDULING               = 245
	SYS_DEBUG_OUTPUT                     = 246
	SYS_KTRACE_OUTPUT                    = 247
	SYS_FRAME_BUFFER_UPDATE              = 248
	SYS_REGISTER_MESSAGING_SERVICE       = 249
	SYS_UNREGISTER_MESSAGING_SERVICE     = 250
	SYS_CLEAR_CACHES                     = 251
	SYS_CPU_ENABLED                      = 252
	SYS_SET_CPU_ENABLED                  = 253
	SYS_GET_CPUID                        = 254
	SYS_GET_NEXT_DISK_DEVICE_ID          = 255
	SYS_FIND_DISK_DEVICE                 = 256
	SYS_FIND_PARTITION                   = 257
	SYS_FIND_FILE_DISK_DEVICE            = 258
	SYS_GET_DISK_DEVICE_DATA             = 259
	SYS_REGISTER_FILE_DEVICE             = 260
	SYS_UNREGISTER_FILE_DEVICE           = 261
	SYS_GET_FILE_DISK_DEVICE_PATH        = 262
	SYS_GET_DISK_SYSTEM_INFO             = 263
	SYS_GET_NEXT_DISK_SYSTEM_INFO        = 264
	SYS_FIND_DISK_SYSTEM                 = 265
	SYS_DEFRAGMENT_PARTITION             = 266
	SYS_REPAIR_PARTITION                 = 267
	SYS_RESIZE_PARTITION                 = 268
	SYS_MOVE_PARTITION                   = 269
	SYS_SET_PARTITION_NAME               = 270
	SYS_SET_PARTITION_CONTENT_NAME       = 271
	SYS_SET_PARTITION_TYPE               = 272
	SYS_SET_PARTITION_PARAMETERS         = 273
	SYS_SET_PARTITION_CONTENT_PARAMETERS = 274
	SYS_INITIALIZE_PARTITION             = 275
	SYS_UNINITIALIZE_PARTITION           = 276
	SYS_CREATE_CHILD_PARTITION           = 277
	SYS_DELETE_CHILD_PARTITION           = 278
	SYS_START_WATCHING_DISKS             = 279
	SYS_STOP_WATCHING_DISKS              = 280
)
