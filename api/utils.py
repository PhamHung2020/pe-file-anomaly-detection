import math

SIZE_UNIT_TABLE = {
    'B': 1,
    'KB': 1024,
    'MB': 1024*1024,
    'GB': 1024*1024*1024
}

ACCEPTABLE_UNIT = ('B', 'KB', 'MB', 'GB')

def convert_size(size: float, in_unit: str = 'B', out_unit: str = 'KB'):
    if in_unit not in ACCEPTABLE_UNIT or out_unit not in ACCEPTABLE_UNIT:
        return math.nan

    if in_unit == out_unit:
        return size
    
    return size * SIZE_UNIT_TABLE[in_unit] / SIZE_UNIT_TABLE[out_unit]
    