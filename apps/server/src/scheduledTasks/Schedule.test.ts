import { describe, expect, it } from "@effect/vitest";
import * as DateTime from "effect/DateTime";

import { isMissedFixedTimeRun, isSameSchedule, nextScheduledRunAt } from "./Schedule.ts";

describe("scheduled task schedule calculation", () => {
  it("skips to the next matching fixed-time weekday", () => {
    const next = nextScheduledRunAt(
      { type: "fixed_time", timeOfDay: "09:00", weekdays: [1, 2, 3, 4, 5] },
      DateTime.makeZonedUnsafe(
        {
          year: 2026,
          month: 7,
          day: 3,
          hour: 10,
          minute: 0,
          second: 0,
          millisecond: 0,
        },
        { timeZone: "America/Los_Angeles", adjustForTimeZone: true },
      ),
    );
    const parts = next ? DateTime.toParts(next) : null;
    expect(parts?.weekDay).toBe(1);
    expect(parts?.hour).toBe(9);
    expect(parts?.minute).toBe(0);
  });

  it("compares schedules structurally", () => {
    expect(
      isSameSchedule(
        { type: "once", runAt: "2026-11-01T03:00:00-05:00" },
        { type: "once", runAt: "2026-11-01T08:00:00.000Z" },
      ),
    ).toBe(true);
    expect(
      isSameSchedule({ type: "interval", everyMs: 60_000 }, { type: "interval", everyMs: 60_000 }),
    ).toBe(true);
    expect(
      isSameSchedule({ type: "interval", everyMs: 60_000 }, { type: "interval", everyMs: 30_000 }),
    ).toBe(false);
    expect(
      isSameSchedule(
        { type: "fixed_time", timeOfDay: "09:00", weekdays: [1, 2] },
        { type: "fixed_time", timeOfDay: "09:00", weekdays: [1, 2] },
      ),
    ).toBe(true);
    expect(
      isSameSchedule(
        { type: "fixed_time", timeOfDay: "09:00", weekdays: [5, 1] },
        { type: "fixed_time", timeOfDay: "09:00", weekdays: [1, 5, 5] },
      ),
    ).toBe(true);
    expect(
      isSameSchedule(
        { type: "fixed_time", timeOfDay: "09:00" },
        { type: "fixed_time", timeOfDay: "09:00", weekdays: [0, 1, 2, 3, 4, 5, 6] },
      ),
    ).toBe(true);
    expect(
      isSameSchedule(
        { type: "fixed_time", timeOfDay: "09:00", weekdays: [] },
        { type: "fixed_time", timeOfDay: "09:00" },
      ),
    ).toBe(true);
    expect(
      isSameSchedule(
        { type: "fixed_time", timeOfDay: "09:00", weekdays: [1, 2] },
        { type: "fixed_time", timeOfDay: "09:00", weekdays: [1, 3] },
      ),
    ).toBe(false);
    expect(
      isSameSchedule(
        { type: "fixed_time", timeOfDay: "09:00" },
        { type: "fixed_time", timeOfDay: "09:30" },
      ),
    ).toBe(false);
    expect(
      isSameSchedule(
        { type: "interval", everyMs: 60_000 },
        { type: "fixed_time", timeOfDay: "09:00" },
      ),
    ).toBe(false);
    expect(
      isSameSchedule(
        { type: "cron", expression: "0 9-17 * * 1-5" },
        { type: "cron", expression: "  0   9-17  *  *  1-5 " },
      ),
    ).toBe(true);
    expect(
      isSameSchedule(
        { type: "cron", expression: "0 9-17 * * 1-5" },
        { type: "cron", expression: "*/30 9-17 * * 1-5" },
      ),
    ).toBe(false);
    expect(
      isSameSchedule(
        { type: "cron", expression: "0 9 * * 1-5" },
        { type: "fixed_time", timeOfDay: "09:00", weekdays: [1, 2, 3, 4, 5] },
      ),
    ).toBe(false);
  });

  it("advances weekday working-hours cron schedules across weekends and within hours", () => {
    // Friday 2026-07-03 17:30 -> Monday 2026-07-06 09:00
    const afterHours = nextScheduledRunAt(
      { type: "cron", expression: "0 9-17 * * 1-5" },
      DateTime.makeZonedUnsafe(
        { year: 2026, month: 7, day: 3, hour: 17, minute: 30, second: 0, millisecond: 0 },
        { timeZone: "America/Los_Angeles", adjustForTimeZone: true },
      ),
    );
    const afterHoursParts = afterHours ? DateTime.toParts(afterHours) : null;
    expect(afterHoursParts?.year).toBe(2026);
    expect(afterHoursParts?.month).toBe(7);
    expect(afterHoursParts?.day).toBe(6);
    expect(afterHoursParts?.weekDay).toBe(1);
    expect(afterHoursParts?.hour).toBe(9);
    expect(afterHoursParts?.minute).toBe(0);

    // Monday 2026-07-06 09:00 -> Monday 2026-07-06 09:30
    const nextSlot = nextScheduledRunAt(
      { type: "cron", expression: "*/30 9-16 * * MON-FRI" },
      DateTime.makeZonedUnsafe(
        { year: 2026, month: 7, day: 6, hour: 9, minute: 0, second: 0, millisecond: 0 },
        { timeZone: "America/Los_Angeles", adjustForTimeZone: true },
      ),
    );
    const nextSlotParts = nextSlot ? DateTime.toParts(nextSlot) : null;
    expect(nextSlotParts?.day).toBe(6);
    expect(nextSlotParts?.hour).toBe(9);
    expect(nextSlotParts?.minute).toBe(30);
  });

  it("preserves local wall clock across DST spring-forward and does not double-fire on fall-back", () => {
    // Spring-forward: 2026-03-08 in America/Los_Angeles
    const springNext = nextScheduledRunAt(
      { type: "cron", expression: "0 9 * * *" },
      DateTime.makeZonedUnsafe(
        { year: 2026, month: 3, day: 7, hour: 10, minute: 0, second: 0, millisecond: 0 },
        { timeZone: "America/Los_Angeles", adjustForTimeZone: true },
      ),
    );
    const springParts = springNext ? DateTime.toParts(springNext) : null;
    expect(springParts?.month).toBe(3);
    expect(springParts?.day).toBe(8);
    expect(springParts?.hour).toBe(9);
    expect(springParts?.minute).toBe(0);

    // Fall-back: 2026-11-01 01:30 occurs twice in America/Los_Angeles
    const firstOverlap = nextScheduledRunAt(
      { type: "cron", expression: "30 1 * * *" },
      DateTime.makeZonedUnsafe(
        { year: 2026, month: 11, day: 1, hour: 0, minute: 30, second: 0, millisecond: 0 },
        { timeZone: "America/Los_Angeles", adjustForTimeZone: true },
      ),
    );
    expect(firstOverlap).not.toBeNull();
    const afterOverlap = nextScheduledRunAt(
      { type: "cron", expression: "30 1 * * *" },
      firstOverlap!,
    );
    const afterOverlapParts = afterOverlap ? DateTime.toParts(afterOverlap) : null;
    expect(afterOverlapParts?.month).toBe(11);
    expect(afterOverlapParts?.day).toBe(2);
    expect(afterOverlapParts?.hour).toBe(1);
    expect(afterOverlapParts?.minute).toBe(30);
  });

  it("returns null for unmatchable cron expressions instead of throwing", () => {
    const from = DateTime.makeUnsafe("2026-07-03T16:00:00.000Z");
    expect(nextScheduledRunAt({ type: "cron", expression: "0 0 30 2 *" }, from)).toBeNull();
  });

  it("applies the missed-run grace window to cron schedules", () => {
    const dueAt = DateTime.makeUnsafe("2026-07-03T16:00:00.000Z");
    const schedule = { type: "cron", expression: "0 9-17 * * 1-5" } as const;
    expect(isMissedFixedTimeRun(schedule, dueAt, DateTime.add(dueAt, { minutes: 5 }))).toBe(false);
    expect(isMissedFixedTimeRun(schedule, dueAt, DateTime.add(dueAt, { minutes: 11 }))).toBe(true);
  });
});
