
Flash raw operations performance
================================

In parallelism x8 (ie. disabled):
 * 128k sector erase from full-1's sector: 2'
 * 128k sector erase from full-0's sector: 1'
 * 128k sector write to 0: 1'

In parallelism x32 (ie. maximal):
 * 128k sector erase from full-1's sector: 1'
 * 128k sector erase from full-0's sector: 800ms
 * 128k sector write to 0 from full-1's sector: 350ms


FS defrag performance
=====================

(x32 parallelism)

128k, 1-byte tag / 1-byte data : ~3s (2800ms)
