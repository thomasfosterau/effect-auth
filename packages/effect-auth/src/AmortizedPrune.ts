import * as MutableHashMap from "effect/MutableHashMap";
import * as Arr from "effect/Array";

/**
 * Prune a `MutableHashMap` of the entries `isStale` picks, but only once it
 * has doubled in size since the last prune (and holds at least `floor`
 * entries). Called on every write, it costs amortized O(1) and keeps an
 * in-process store bounded by its live entries.
 */
export const amortizedPrune = <K, V>(
  map: MutableHashMap.MutableHashMap<K, V>,
  floor = 1024,
): ((isStale: (value: V, key: K) => boolean) => void) => {
  let next = floor;
  return (isStale) => {
    if (MutableHashMap.size(map) < next) return;
    Arr.forEach(Arr.fromIterable(map), ([key, value]) => {
      if (isStale(value, key)) MutableHashMap.remove(map, key);
    });
    next = Math.max(floor, MutableHashMap.size(map) * 2);
  };
};
