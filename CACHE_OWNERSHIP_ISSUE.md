# Page Cache Ownership & Memory Issue

## 문제 요약

11GB memcached restore 시 두 가지 문제 발생:

### 1. OOM (기존 코드)
- prefetch worker가 S3에서 IOV data를 `xmalloc`으로 할당
- `cache_store_iov()`가 data를 **deep copy**해서 cache에 저장
- worker의 원본 `data`가 **free 안 됨** (메모리 leak)
- 결과: worker buffer + cache copy = 2배 메모리 사용 → 11GB × 2 = 22GB → OOM (16GB VM)

### 2. Segfault (ownership 이전 시도 시)
ownership 이전 방식으로 변경 시도:
- `cache_store_iov()`에서 `entry->data = data` (copy 대신 직접 대입)
- `cache_lookup_iov_for_fault()`에서 `*data_out = entry->data` + entry 삭제 (copy 대신 ownership 이전)

**실패 원인 (추정):**
- `ip=0x0` segfault → code page가 로드 안 된 상태에서 실행 시도
- cache lookup에서 entry를 즉시 삭제하면서, 동시에 prefetch worker가 같은 entry를 참조할 가능성
- 또는 cache_mark_restored()가 이미 삭제된 entry를 다시 삭제 시도 → use-after-free
- 또는 memory pressure eviction이 prefetch worker가 아직 사용 중인 entry를 evict

**조사 필요 사항:**
1. `cache_lookup_iov_for_fault()`에서 entry 삭제 시 lock 안에서 하지만, 삭제 후 caller가 data를 사용하는 동안 다른 thread가 같은 주소에 새 allocation을 할 수 있음
2. `cache_mark_restored()`가 이미 삭제된 entry에 대해 호출됨 → lookup_internal이 없으므로 no-op이지만, rb_tree가 corruption되었을 가능성
3. memory pressure eviction의 `get_available_memory()`가 `/proc/meminfo`를 읽는 오버헤드

## 현재 해결 방식 (deep copy + immediate release + memory pressure)

```
cache_store_iov():
  entry->data = xmalloc(size);
  memcpy(entry->data, data, size);  // deep copy
  // caller는 자기 data를 free해야 함

cache_lookup_iov_for_fault():
  data_copy = xmalloc(entry->data_size);
  memcpy(data_copy, entry->data, entry->data_size);  // deep copy
  *data_out = data_copy;
  // 즉시 cache에서 entry 삭제 (메모리 회수)
  rb_erase(&entry->node, ...);
  xfree(entry->data);
  xfree(entry);

prefetch worker:
  data = xmalloc(size);
  fetch_from_s3(data);
  cache_store_iov(data, size);
  xfree(data);  // worker buffer 해제

cache_evict_to_limit():
  if (max_bytes > 0) → explicit limit eviction
  if (max_bytes == 0) → memory pressure 기반 eviction
    check /proc/meminfo MemAvailable
    if available < 1GB → evict oldest entries
```

### 메모리 flow (1개 IOV, 4MB 기준)

```
시점            worker_buf  cache_entry  process_mem  합계
────────────────────────────────────────────────────────
fetch 완료      +4MB        -           -            4MB
cache_store     +4MB        +4MB        -            8MB  (peak: deep copy)
worker free     -           +4MB        -            4MB
fault hit       -           +4MB*       +4MB         8MB  (peak: copy to process)
cache remove    -           -           +4MB         4MB
uffd_copy free  -           -           +4MB         4MB  (final: process owns)
```

*cache hit 시 data_copy로 추가 4MB 임시 할당

### Peak memory 추정 (11GB, 4 workers)
- Process RSS: ~11GB (restored pages)
- Prefetch peak: 4 workers × 4MB × 2 (worker_buf + cache_copy) = 32MB
- Cache: eviction 전 최대 = available memory - 1GB
- 실제 peak: process + cache + worker buffers

## 더 나은 해결 방향 (향후)

### 방향 1: Zero-copy with reference counting
```c
struct cache_entry {
    void *data;
    atomic_int refcount;  // 1=cache only, 2=cache+consumer
};
// lookup: refcount++ → consumer 사용 후 refcount--
// refcount 0이면 free
```

### 방향 2: mmap-based cache
```c
// cache data를 mmap(MAP_ANONYMOUS)로 할당
// uffd_copy 시 UFFDIO_COPY의 src로 직접 사용
// copy 불필요 (kernel이 page table만 수정)
```

### 방향 3: Prefetch rate limiting
```c
// prefetch worker가 cache size를 모니터링
// cache가 limit에 가까우면 worker가 sleep
// fault가 cache를 소비하면 worker 재개
```

## 관련 파일
- `criu/page-cache.c` — cache store/lookup/evict/cleanup
- `criu/prefetch.c` — prefetch worker의 cache_store 호출
- `criu/uffd.c:1318` — fault handler의 cache_lookup 호출
