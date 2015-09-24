#include "Config.h"
int g_num_worker_threads = 11;
int g_port_num = 8484;
int g_listen_backlog = 20000;
int g_hint_num_of_timeouts = 10;

//const char* g_listening_ip = "172.16.4.40";
const char* g_listening_ip;
int g_tcp_conn_r_buf = 10240;

/*
 *
 int g_tcp_conn_w_buf; 
 *
 */

int g_tcp_conn_r_timeout = 5000;
int g_tcp_conn_w_timeout = 100;
int g_hint_url_size = 1;
int g_hint_n_qparams = 1;
int g_hint_n_headers = 1;
int g_hint_n_cookies = 1;
int g_hint_req_body_size = 1;
int g_hint_res_body_size = 1;
int g_hint_res_header_size = 1;
