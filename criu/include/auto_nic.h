#ifndef __CR_AUTO_NIC_H__
#define __CR_AUTO_NIC_H__

/*
 * Cloud-instance NIC bandwidth detection used by CRIU's S3 upload_pool
 * (dump) and prefetch worker pool (restore) to pick worker counts that
 * match the host's network speed.
 *
 * Detection order (short-circuits on first success; cached via pthread_once):
 *   1. Env var CRIU_NIC_MBPS  — raw integer, explicit override
 *   2. Env var AWS_INSTANCE_TYPE / AZURE_VM_SIZE / GCP_MACHINE_TYPE
 *      — cloud instance identifier, looked up in the hardcoded table
 *        (populated from contrib/nic-table.csv at build time).
 *   3. IMDSv2 probe (AWS only for now; Azure/GCP placeholders exist).
 *      Inside Kubernetes pods this requires http-put-response-hop-limit
 *      >= 2 on the EC2 node. EKS defaults to 2 since 2020.
 *   4. /sys/class/net/<default>/speed  — unreliable on cloud (ENA/gVNIC
 *      report empty on most providers) but works on baremetal.
 *   5. Return -1 → caller uses its static default.
 *
 * Thread-safe. Total detection cost ≤100 ms (IMDSv2 TCP timeout); zero
 * cost if env var set.
 */
extern int auto_nic_mbps(void);

/*
 * Compute an ideal worker count for a libcurl-based CURLM upload pool
 * or a pthread prefetch pool given the detected NIC.
 *
 *   workers = min( max_cap,
 *                  ncpu - 1,               (reserve 1 for main thread)
 *                  nic_mbps / per_conn_mbps + headroom )
 *
 * per_conn_mbps is the empirical per-connection throughput for the use
 * case — ~280 Mbps per slot for S3 PUT, ~480 Mbps per worker for S3 GET
 * on libcurl in our EC2 measurements. Lower value = more workers to
 * saturate the NIC.
 *
 * Returns at least 4. nic_mbps <= 0 returns 8 (safe default).
 */
extern int auto_pool_workers(int nic_mbps, int ncpu, int max_cap,
			     int per_conn_mbps);

#endif /* __CR_AUTO_NIC_H__ */
