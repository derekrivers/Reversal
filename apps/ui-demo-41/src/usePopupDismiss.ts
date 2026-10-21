import { useEffect, useRef } from 'react';

/** Dismiss a local menu without changing browser history or the screen underneath. */
export function usePopupDismiss(open: boolean, close: () => void, insideSelector: string) {
  const closeRef = useRef(close);
  closeRef.current = close;
  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') closeRef.current();
    };
    const onDown = (event: MouseEvent) => {
      if (event.target instanceof Element && !event.target.closest(insideSelector)) closeRef.current();
    };
    document.addEventListener('keydown', onKey);
    document.addEventListener('mousedown', onDown);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('mousedown', onDown);
    };
  }, [open, insideSelector]);
}
