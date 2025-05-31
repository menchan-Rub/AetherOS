fn allocate_slab_object(cache: &SlabCache, node: usize) -> *mut u8 {
    // NUMAノードごとにページプールを持ち、キャッシュラインアライメントも考慮
    let page = page_manager::alloc_page_on_node(node, cache.object_size, cache.align);
    let obj = page_manager::find_free_object(page, cache.object_size, cache.align);
    obj
} 