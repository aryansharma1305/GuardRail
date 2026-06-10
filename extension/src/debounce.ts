/**
 * debounce.ts
 * Returns a debounced version of `func` that delays invoking it until
 * `wait` milliseconds have elapsed since the last invocation.
 */
export function debounce(func: Function, wait: number): Function {
  let timeoutId: ReturnType<typeof setTimeout> | undefined;

  return function (this: unknown, ...args: unknown[]) {
    if (timeoutId !== undefined) {
      clearTimeout(timeoutId);
    }

    timeoutId = setTimeout(() => {
      timeoutId = undefined;
      func.apply(this, args);
    }, wait);
  };
}
