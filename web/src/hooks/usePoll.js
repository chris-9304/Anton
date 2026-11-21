import { useCallback, useEffect, useRef, useState } from "react";
import { createPoller } from "../services/polling.js";

export function usePoll(load, interval = 3000) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const poller = useRef(null);
  useEffect(() => {
    const task = createPoller({
      load,
      interval,
      onData(value) {
        setData(value);
        setError(null);
        setLoading(false);
      },
      onError(error) {
        setError(error.message);
        setLoading(false);
      },
    });
    poller.current = task;
    return () => {
      task.dispose();
      poller.current = null;
    };
  }, [load, interval]);
  const refresh = useCallback(() => poller.current?.refresh(), []);
  return { data, error, loading, refresh };
}
