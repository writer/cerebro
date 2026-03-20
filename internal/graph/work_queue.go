package graph

import "sync/atomic"

type traversalWorkDeque struct {
	top    atomic.Int64
	bottom atomic.Int64
	slots  []atomic.Int64
	mask   int64
}

type traversalWorkQueue struct {
	deques []traversalWorkDeque
}

func newTraversalWorkQueue(workers, capacity int) *traversalWorkQueue {
	if workers <= 0 {
		workers = 1
	}
	if capacity < 2 {
		capacity = 2
	}
	deques := make([]traversalWorkDeque, workers)
	for index := range deques {
		deques[index] = newTraversalWorkDeque(capacity)
	}
	return &traversalWorkQueue{deques: deques}
}

func newTraversalWorkDeque(capacity int) traversalWorkDeque {
	size := nextTraversalQueuePowerOfTwo(capacity)
	return traversalWorkDeque{
		slots: make([]atomic.Int64, size),
		mask:  int64(size - 1),
	}
}

func nextTraversalQueuePowerOfTwo(value int) int {
	if value < 2 {
		return 2
	}
	size := 1
	for size < value {
		size <<= 1
	}
	return size
}

func (q *traversalWorkQueue) seedContiguous(itemCount int) {
	if q == nil || itemCount <= 0 || len(q.deques) == 0 {
		return
	}
	chunkSize := (itemCount + len(q.deques) - 1) / len(q.deques)
	for worker := range q.deques {
		start := worker * chunkSize
		if start >= itemCount {
			break
		}
		end := start + chunkSize
		if end > itemCount {
			end = itemCount
		}
		for index := start; index < end; index++ {
			_ = q.deques[worker].pushBottom(index)
		}
	}
}

func (q *traversalWorkQueue) next(worker int) (int, bool) {
	if q == nil || worker < 0 || worker >= len(q.deques) {
		return 0, false
	}
	if item, ok := q.deques[worker].popBottom(); ok {
		return item, true
	}
	for offset := 1; offset < len(q.deques); offset++ {
		victim := (worker + offset) % len(q.deques)
		if item, ok := q.deques[victim].stealTop(); ok {
			return item, true
		}
	}
	return 0, false
}

func (q *traversalWorkQueue) push(worker, item int) bool {
	if q == nil || worker < 0 || worker >= len(q.deques) {
		return false
	}
	return q.deques[worker].pushBottom(item)
}

func (d *traversalWorkDeque) pushBottom(item int) bool {
	if d == nil || item < 0 {
		return false
	}
	bottom := d.bottom.Load()
	top := d.top.Load()
	if bottom-top >= int64(len(d.slots)) {
		return false
	}
	d.slots[bottom&d.mask].Store(int64(item) + 1)
	d.bottom.Store(bottom + 1)
	return true
}

func (d *traversalWorkDeque) popBottom() (int, bool) {
	if d == nil {
		return 0, false
	}

	bottom := d.bottom.Add(-1)
	top := d.top.Load()
	if top > bottom {
		d.bottom.Store(top)
		return 0, false
	}

	item := int(d.slots[bottom&d.mask].Load() - 1)
	if top == bottom {
		if !d.top.CompareAndSwap(top, top+1) {
			d.bottom.Store(top + 1)
			return 0, false
		}
		d.bottom.Store(top + 1)
	}
	return item, true
}

func (d *traversalWorkDeque) stealTop() (int, bool) {
	if d == nil {
		return 0, false
	}
	for {
		top := d.top.Load()
		bottom := d.bottom.Load()
		if top >= bottom {
			return 0, false
		}
		item := int(d.slots[top&d.mask].Load() - 1)
		if d.top.CompareAndSwap(top, top+1) {
			return item, true
		}
	}
}
