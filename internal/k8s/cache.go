package k8s

import (
	"container/list"
	"sync"
)

type cacheItem[K comparable, V any] struct {
	key   K
	value V
}

type lruCache[K comparable, V any] struct {
	mu        sync.Mutex
	capacity  int
	items     map[K]*list.Element
	evictList *list.List
}

func newLRUCache[K comparable, V any](capacity int) *lruCache[K, V] {
	return &lruCache[K, V]{
		capacity:  capacity,
		items:     make(map[K]*list.Element),
		evictList: list.New(),
	}
}

func (c *lruCache[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.evictList.MoveToFront(elem)
		return elem.Value.(*cacheItem[K, V]).value, true
	}
	var zero V
	return zero, false
}

func (c *lruCache[K, V]) Add(key K, val V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Existing item update
	if elem, ok := c.items[key]; ok {
		c.evictList.MoveToFront(elem)
		elem.Value.(*cacheItem[K, V]).value = val
		return
	}

	// Add new item
	elem := c.evictList.PushFront(&cacheItem[K, V]{key: key, value: val})
	c.items[key] = elem

	// Evict oldest if full
	if c.evictList.Len() > c.capacity {
		oldest := c.evictList.Back()
		if oldest != nil {
			c.evictList.Remove(oldest)
			kv := oldest.Value.(*cacheItem[K, V])
			delete(c.items, kv.key)
		}
	}
}
