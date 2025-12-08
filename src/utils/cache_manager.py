import hashlib
import json
from typing import Any, Dict, Optional
from functools import lru_cache


class CacheManager:
    """
    缓存管理器，使用LRU缓存策略
    """
    
    def __init__(self, max_size: int = 128):
        """
        初始化缓存管理器

        Args:
            max_size: 缓存最大大小
        """
        self.max_size = max_size
        # 使用LRU缓存装饰器来实现缓存功能
        self._cache_get = lru_cache(maxsize=max_size)(self._get_from_cache_impl)
        self._cache_set = {}
    
    def _get_cache_key(self, *args, **kwargs) -> str:
        """
        生成缓存键
        """
        key_data = {
            'args': args,
            'kwargs': kwargs
        }
        key_str = json.dumps(key_data, sort_keys=True, default=str)
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def get(self, key: str) -> Optional[Any]:
        """
        获取缓存值

        Args:
            key: 缓存键

        Returns:
            缓存值或None
        """
        # 对于简单的LRU缓存，我们使用一个单独的字典来存储值
        return self._cache_set.get(key)
    
    def set(self, key: str, value: Any):
        """
        设置缓存值

        Args:
            key: 缓存键
            value: 缓存值
        """
        # 如果缓存超出大小限制，则清除LRU项
        if len(self._cache_set) >= self.max_size:
            # 简单的方式，只是删除最早添加的项直到空间足够
            oldest_keys = list(self._cache_set.keys())[:max(1, self.max_size // 4)]
            for k in oldest_keys:
                if k in self._cache_set:
                    del self._cache_set[k]
        
        self._cache_set[key] = value
    
    def clear(self):
        """
        清空缓存
        """
        self._cache_set.clear()
        self._cache_get.cache_clear()
    
    def _get_from_cache_impl(self, key: str) -> Optional[Any]:
        """
        实际的缓存获取实现
        """
        return self._cache_set.get(key)
    
    def get_stats(self) -> Dict[str, Any]:
        """
        获取缓存统计信息

        Returns:
            缓存统计信息
        """
        return {
            'size': len(self._cache_set),
            'max_size': self.max_size,
            'keys': list(self._cache_set.keys())
        }


# 全局缓存实例
global_cache = CacheManager()