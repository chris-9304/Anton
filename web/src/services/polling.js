/** One in-flight refresh; stale responses and hidden tabs never schedule more work. */
export function createPoller({
  load,
  onData,
  onError,
  interval = 3000,
  visibility = document,
}) {
  let disposed = false;
  let timer;
  let controller;
  let generation = 0;

  async function refresh() {
    if (disposed || visibility.hidden) return;
    clearTimeout(timer);
    controller?.abort();
    controller = new AbortController();
    const current = ++generation;
    try {
      const data = await load({ signal: controller.signal });
      if (!disposed && current === generation) onData(data);
    } catch (error) {
      if (!disposed && current === generation && error.name !== "AbortError")
        onError(error);
    } finally {
      if (!disposed && current === generation && interval && !visibility.hidden)
        timer = setTimeout(refresh, interval);
    }
  }

  function onVisibility() {
    clearTimeout(timer);
    generation += 1;
    controller?.abort();
    if (!visibility.hidden) void refresh();
  }
  visibility.addEventListener("visibilitychange", onVisibility);
  void refresh();
  return {
    refresh,
    dispose() {
      disposed = true;
      generation += 1;
      clearTimeout(timer);
      controller?.abort();
      visibility.removeEventListener("visibilitychange", onVisibility);
    },
  };
}
