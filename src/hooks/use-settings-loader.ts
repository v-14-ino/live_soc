"use client";

import { useEffect } from "react";
import { useAppStore } from "@/lib/store";
import { api } from "@/lib/api-client";

export function useSettingsLoader() {
  const setSettings = useAppStore((s) => s.setSettings);
  useEffect(() => {
    let alive = true;
    api
      .getSettings()
      .then((s) => {
        if (alive) setSettings(s);
      })
      .catch(() => {
        /* use defaults */
      });
    return () => {
      alive = false;
    };
  }, [setSettings]);
}
