/**
 * Permission-gated Northwind domain service.
 *
 * Each operation begins with `Auth.requirePermission(userId, resource, action)`,
 * which fails with `PermissionDeniedError` if the caller's roles do not allow it.
 */

import { Context, Effect, Layer } from "effect";
import * as Auth from "effect-auth";
import {
  type Customer,
  type Order,
  type OrderDetail,
  type Product,
  customers,
  nextId,
  orders,
  products,
} from "./domain.ts";

export interface NewCustomerInput {
  readonly companyName: string;
  readonly contactName: string;
  readonly phone: string;
}

export interface PlaceOrderInput {
  readonly customerId: string;
  readonly items: ReadonlyArray<{ productId: string; quantity: number }>;
}

export interface SalesReport {
  readonly orderCount: number;
  readonly totalRevenue: number;
}

export interface NorthwindService {
  readonly listProducts: (
    userId: string,
  ) => Effect.Effect<
    ReadonlyArray<Product>,
    Auth.PermissionDeniedError,
    Auth.AuthorizationPolicyTag
  >;

  readonly createCustomer: (
    userId: string,
    input: NewCustomerInput,
  ) => Effect.Effect<Customer, Auth.PermissionDeniedError, Auth.AuthorizationPolicyTag>;

  readonly placeOrder: (
    userId: string,
    input: PlaceOrderInput,
  ) => Effect.Effect<
    Order,
    Auth.PermissionDeniedError | Auth.AuthError,
    Auth.AuthorizationPolicyTag
  >;

  readonly discontinueProduct: (
    userId: string,
    productId: string,
  ) => Effect.Effect<
    Product,
    Auth.PermissionDeniedError | Auth.AuthError,
    Auth.AuthorizationPolicyTag
  >;

  readonly viewSalesReport: (
    userId: string,
  ) => Effect.Effect<SalesReport, Auth.PermissionDeniedError, Auth.AuthorizationPolicyTag>;
}

export class NorthwindServiceTag extends Context.Tag("@northwind/Service")<
  NorthwindServiceTag,
  NorthwindService
>() {}

const makeNorthwind = (): NorthwindService => ({
  listProducts: (userId) =>
    Effect.gen(function* () {
      yield* Auth.requirePermission(userId, "product", "read");
      return Array.from(products.values());
    }),

  createCustomer: (userId, input) =>
    Effect.gen(function* () {
      yield* Auth.requirePermission(userId, "customer", "create");
      const customer: Customer = {
        id: nextId("cust"),
        companyName: input.companyName,
        contactName: input.contactName,
        phone: input.phone,
        createdByEmployeeId: userId,
      };
      customers.set(customer.id, customer);
      return customer;
    }),

  placeOrder: (userId, input) =>
    Effect.gen(function* () {
      yield* Auth.requirePermission(userId, "order", "create");

      if (!customers.has(input.customerId)) {
        return yield* Effect.fail(
          new Auth.AuthError({ message: `Unknown customer: ${input.customerId}` }),
        );
      }

      const details: OrderDetail[] = [];
      for (const item of input.items) {
        const product = products.get(item.productId);
        if (!product) {
          return yield* Effect.fail(
            new Auth.AuthError({ message: `Unknown product: ${item.productId}` }),
          );
        }
        if (product.discontinued) {
          return yield* Effect.fail(
            new Auth.AuthError({ message: `Product is discontinued: ${product.name}` }),
          );
        }
        details.push({
          productId: product.id,
          quantity: item.quantity,
          unitPrice: product.unitPrice,
        });
      }

      const order: Order = {
        id: nextId("ord"),
        customerId: input.customerId,
        employeeId: userId,
        orderDate: new Date(),
        details,
      };
      orders.set(order.id, order);
      return order;
    }),

  discontinueProduct: (userId, productId) =>
    Effect.gen(function* () {
      yield* Auth.requirePermission(userId, "product", "update");
      const product = products.get(productId);
      if (!product) {
        return yield* Effect.fail(new Auth.AuthError({ message: `Unknown product: ${productId}` }));
      }
      const updated: Product = { ...product, discontinued: true };
      products.set(productId, updated);
      return updated;
    }),

  viewSalesReport: (userId) =>
    Effect.gen(function* () {
      yield* Auth.requirePermission(userId, "report", "read");
      let total = 0;
      for (const order of orders.values()) {
        for (const detail of order.details) {
          total += detail.quantity * detail.unitPrice;
        }
      }
      return { orderCount: orders.size, totalRevenue: total };
    }),
});

export const NorthwindServiceLayer = Layer.succeed(NorthwindServiceTag, makeNorthwind());
