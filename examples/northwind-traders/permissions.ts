/**
 * Northwind roles and permissions.
 *
 * Resources: product, customer, order, report.
 * Actions:   create, read, update, delete.
 *
 * Roles are stored against employee ids in `userRoles`. The library's
 * `RoleStore` interface is satisfied by reading from that map.
 */

import { Effect } from "effect";
import type * as Auth from "effect-auth";
import { userRoles } from "./domain.ts";

export const NorthwindRoles = {
  SalesRep: "SalesRep",
  SalesManager: "SalesManager",
  InventoryManager: "InventoryManager",
  Admin: "Admin",
} as const;

export type NorthwindRole = (typeof NorthwindRoles)[keyof typeof NorthwindRoles];

type Permission = { resource: string; action: string };

const all = (resource: string): ReadonlyArray<Permission> =>
  (["create", "read", "update", "delete"] as const).map((action) => ({ resource, action }));

const rolePermissions = new Map<string, ReadonlyArray<Permission>>([
  [
    NorthwindRoles.SalesRep,
    [
      { resource: "product", action: "read" },
      { resource: "customer", action: "create" },
      { resource: "customer", action: "read" },
      { resource: "order", action: "create" },
      { resource: "order", action: "read" },
    ],
  ],
  [
    NorthwindRoles.SalesManager,
    [
      { resource: "product", action: "read" },
      ...all("customer"),
      ...all("order"),
      { resource: "report", action: "read" },
    ],
  ],
  [
    NorthwindRoles.InventoryManager,
    [
      ...all("product"),
      { resource: "customer", action: "read" },
      { resource: "order", action: "read" },
    ],
  ],
  [
    NorthwindRoles.Admin,
    [...all("product"), ...all("customer"), ...all("order"), ...all("report")],
  ],
]);

export const roleStore: Auth.RoleStoreShape = {
  getUserRoles: (userId) => Effect.succeed(userRoles.get(userId) ?? []),
  getRolePermissions: (role) => Effect.succeed(rolePermissions.get(role) ?? []),
};
