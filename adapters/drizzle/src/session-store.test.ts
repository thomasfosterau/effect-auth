import { describe, it, expect, vi } from "vitest"
import { Effect, Context } from "effect"
import { SessionStore, UserStore, SessionNotFoundError, UserNotFoundError } from "effect-auth"
import type { Session } from "effect-auth"
import { DrizzleDatabase } from "./database.js"
import { makeDrizzleSessionStoreLive } from "./session-store.js"
import { makeDrizzleUserStoreLive } from "./user-store.js"
import { sessionsTable, usersTable } from "./schema.js"

// ---------------------------------------------------------------------------
// Mock helpers
// ---------------------------------------------------------------------------

const now = new Date("2025-01-01T00:00:00.000Z")
const expiresAt = new Date("2025-02-01T00:00:00.000Z")

const sessionRow = {
  id: "session-1",
  userId: "user-1",
  expiresAt,
  createdAt: now,
  lastActivityAt: now,
  attributes: { ip: "127.0.0.1" },
}

const userRow = {
  id: "user-1",
  attributes: { name: "Alice" },
  hashedPassword: "hashed-pw",
}

/**
 * Build a minimal Drizzle-like mock whose query chains resolve with the
 * provided results. Each builder method returns `this` to support chaining,
 * and the terminal builder is thenable (Promise-like).
 */
function makeMockDb(overrides: {
  selectRows?: Record<string, unknown>[]
  insertRows?: Record<string, unknown>[]
  updateRows?: Record<string, unknown>[]
}) {
  const selectRows = overrides.selectRows ?? []
  const insertRows = overrides.insertRows ?? []
  const updateRows = overrides.updateRows ?? []

  const deleteChain = {
    where: vi.fn(() => Promise.resolve([])),
  }

  const updateWhereChain = {
    returning: vi.fn(() => Promise.resolve(updateRows)),
  }

  const updateSetChain = {
    set: vi.fn(() => ({
      where: vi.fn(() => updateWhereChain),
    })),
  }

  const insertReturningChain = {
    returning: vi.fn(() => Promise.resolve(insertRows)),
  }

  const insertValuesChain = {
    values: vi.fn(() => insertReturningChain),
  }

  const selectWhereChain = {
    where: vi.fn(() => Promise.resolve(selectRows)),
  }

  const selectFromChain = {
    from: vi.fn(() => selectWhereChain),
  }

  return {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    select: vi.fn((_columns?: any) => selectFromChain),
    insert: vi.fn(() => insertValuesChain),
    update: vi.fn(() => updateSetChain),
    delete: vi.fn(() => deleteChain),
  }
}

/** Helper: run an Effect against a mocked DrizzleDatabase returning SessionStore */
const runSession = <A, E>(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  mockDb: any,
  program: Effect.Effect<A, E, SessionStore>
) =>
  Effect.runPromise(
    program.pipe(
      Effect.provide(makeDrizzleSessionStoreLive(sessionsTable)),
      Effect.provide(Context.make(DrizzleDatabase, mockDb))
    )
  )

/** Helper: run an Effect against a mocked DrizzleDatabase returning UserStore */
const runUser = <A, E>(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  mockDb: any,
  program: Effect.Effect<A, E, UserStore>
) =>
  Effect.runPromise(
    program.pipe(
      Effect.provide(makeDrizzleUserStoreLive(usersTable)),
      Effect.provide(Context.make(DrizzleDatabase, mockDb))
    )
  )

// ---------------------------------------------------------------------------
// SessionStore tests
// ---------------------------------------------------------------------------

describe("DrizzleSessionStore", () => {
  it("create – inserts a session and returns it", async () => {
    const mockDb = makeMockDb({ insertRows: [sessionRow] })

    const session: Session = {
      id: sessionRow.id,
      userId: sessionRow.userId,
      expiresAt,
      createdAt: now,
      lastActivityAt: now,
      attributes: sessionRow.attributes,
    }

    const result = await runSession(
      mockDb,
      Effect.gen(function* () {
        const store = yield* SessionStore
        return yield* store.create(session)
      })
    )

    expect(result.id).toBe("session-1")
    expect(result.userId).toBe("user-1")
    expect(mockDb.insert).toHaveBeenCalledOnce()
  })

  it("create – wraps DB errors in AuthError", async () => {
    const mockDb = makeMockDb({ insertRows: [] })
    const err = new Error("DB failure")
    const insertReturning = { returning: vi.fn(() => Promise.reject(err)) }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ;(mockDb.insert as any).mockReturnValue({ values: vi.fn(() => insertReturning) })

    const session: Session = {
      id: "s",
      userId: "u",
      expiresAt,
      createdAt: now,
      lastActivityAt: now,
      attributes: {},
    }

    const result = await Effect.runPromise(
      Effect.either(
        Effect.gen(function* () {
          const store = yield* SessionStore
          return yield* store.create(session)
        }).pipe(
          Effect.provide(makeDrizzleSessionStoreLive(sessionsTable)),
          Effect.provide(Context.make(DrizzleDatabase, mockDb))
        )
      )
    )

    expect(result._tag).toBe("Left")
    if (result._tag === "Left") {
      expect(result.left._tag).toBe("AuthError")
    }
  })

  it("get – returns session when found", async () => {
    const mockDb = makeMockDb({ selectRows: [sessionRow] })

    const result = await runSession(
      mockDb,
      Effect.gen(function* () {
        const store = yield* SessionStore
        return yield* store.get("session-1")
      })
    )

    expect(result.id).toBe("session-1")
    expect(result.attributes).toEqual({ ip: "127.0.0.1" })
  })

  it("get – fails with SessionNotFoundError when not found", async () => {
    const mockDb = makeMockDb({ selectRows: [] })

    const result = await Effect.runPromise(
      Effect.either(
        Effect.gen(function* () {
          const store = yield* SessionStore
          return yield* store.get("missing")
        }).pipe(
          Effect.provide(makeDrizzleSessionStoreLive(sessionsTable)),
          Effect.provide(Context.make(DrizzleDatabase, mockDb))
        )
      )
    )

    expect(result._tag).toBe("Left")
    if (result._tag === "Left") {
      const err = result.left
      expect(err).toBeInstanceOf(SessionNotFoundError)
      if (err instanceof SessionNotFoundError) {
        expect(err.sessionId).toBe("missing")
      }
    }
  })

  it("update – updates session and returns it", async () => {
    const updatedRow = { ...sessionRow, lastActivityAt: expiresAt }
    const mockDb = makeMockDb({ updateRows: [updatedRow] })

    const session: Session = {
      id: sessionRow.id,
      userId: sessionRow.userId,
      expiresAt,
      createdAt: now,
      lastActivityAt: expiresAt,
      attributes: sessionRow.attributes,
    }

    const result = await runSession(
      mockDb,
      Effect.gen(function* () {
        const store = yield* SessionStore
        return yield* store.update(session)
      })
    )

    expect(result.lastActivityAt).toEqual(expiresAt)
    expect(mockDb.update).toHaveBeenCalledOnce()
  })

  it("delete – calls db.delete with the correct id", async () => {
    const mockDb = makeMockDb({})

    await runSession(
      mockDb,
      Effect.gen(function* () {
        const store = yield* SessionStore
        return yield* store.delete("session-1")
      })
    )

    expect(mockDb.delete).toHaveBeenCalledOnce()
  })

  it("deleteByUserId – calls db.delete for the given userId", async () => {
    const mockDb = makeMockDb({})

    await runSession(
      mockDb,
      Effect.gen(function* () {
        const store = yield* SessionStore
        return yield* store.deleteByUserId("user-1")
      })
    )

    expect(mockDb.delete).toHaveBeenCalledOnce()
  })
})

// ---------------------------------------------------------------------------
// UserStore tests
// ---------------------------------------------------------------------------

describe("DrizzleUserStore", () => {
  it("get – returns user when found", async () => {
    const mockDb = makeMockDb({ selectRows: [userRow] })

    const result = await runUser(
      mockDb,
      Effect.gen(function* () {
        const store = yield* UserStore
        return yield* store.get("user-1")
      })
    )

    expect(result.id).toBe("user-1")
    expect(result.attributes).toEqual({ name: "Alice" })
  })

  it("get – fails with UserNotFoundError when not found", async () => {
    const mockDb = makeMockDb({ selectRows: [] })

    const result = await Effect.runPromise(
      Effect.either(
        Effect.gen(function* () {
          const store = yield* UserStore
          return yield* store.get("nobody")
        }).pipe(
          Effect.provide(makeDrizzleUserStoreLive(usersTable)),
          Effect.provide(Context.make(DrizzleDatabase, mockDb))
        )
      )
    )

    expect(result._tag).toBe("Left")
    if (result._tag === "Left") {
      const err = result.left
      expect(err).toBeInstanceOf(UserNotFoundError)
      if (err instanceof UserNotFoundError) {
        expect(err.userId).toBe("nobody")
      }
    }
  })

  it("getCredentials – returns hashed password when found", async () => {
    const mockDb = makeMockDb({ selectRows: [{ hashedPassword: "hashed-pw" }] })

    const result = await runUser(
      mockDb,
      Effect.gen(function* () {
        const store = yield* UserStore
        return yield* store.getCredentials("user-1")
      })
    )

    expect(result).toBe("hashed-pw")
  })

  it("getCredentials – fails with UserNotFoundError when hashedPassword is null", async () => {
    const mockDb = makeMockDb({ selectRows: [{ hashedPassword: null }] })

    const result = await Effect.runPromise(
      Effect.either(
        Effect.gen(function* () {
          const store = yield* UserStore
          return yield* store.getCredentials("user-1")
        }).pipe(
          Effect.provide(makeDrizzleUserStoreLive(usersTable)),
          Effect.provide(Context.make(DrizzleDatabase, mockDb))
        )
      )
    )

    expect(result._tag).toBe("Left")
    if (result._tag === "Left") {
      expect(result.left._tag).toBe("UserNotFoundError")
    }
  })
})

