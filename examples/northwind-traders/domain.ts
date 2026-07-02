/**
 * Northwind Traders — domain types and in-memory state.
 *
 * All entities are kept in mutable Maps so the example is self-contained.
 * In a real app you would replace these with database queries.
 */

import type * as Auth from "effect-auth";

// ---------------------------------------------------------------------------
// Entities
// ---------------------------------------------------------------------------

export interface Employee {
  readonly id: string;
  readonly email: string;
  readonly emailVerified: boolean;
  readonly firstName: string;
  readonly lastName: string;
  readonly title: string;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  readonly attributes: Record<string, unknown>;
}

export interface Category {
  readonly id: string;
  readonly name: string;
  readonly description: string;
}

export interface Product {
  readonly id: string;
  readonly name: string;
  readonly unitPrice: number;
  readonly unitsInStock: number;
  readonly categoryId: string;
  readonly discontinued: boolean;
}

export interface Customer {
  readonly id: string;
  readonly companyName: string;
  readonly contactName: string;
  readonly phone: string;
  readonly createdByEmployeeId: string;
}

export interface OrderDetail {
  readonly productId: string;
  readonly quantity: number;
  readonly unitPrice: number;
}

export interface Order {
  readonly id: string;
  readonly customerId: string;
  readonly employeeId: string;
  readonly orderDate: Date;
  readonly details: ReadonlyArray<OrderDetail>;
}

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

// Auth-backing maps
export const employees = new Map<string, Employee>();
export const passwords = new Map<string, string>();
export const sessions = new Map<string, Auth.Session>();
export const userRoles = new Map<string, string[]>();
export const emailVerifications = new Map<string, Auth.EmailVerification>();
export const rateLimits = new Map<string, Auth.RateLimitEntry>();
export const oauthStates = new Map<string, Auth.OAuthState>();
export const oauthAccounts = new Map<string, Auth.OAuthAccount>();

// Northwind domain maps
export const categories = new Map<string, Category>();
export const products = new Map<string, Product>();
export const customers = new Map<string, Customer>();
export const orders = new Map<string, Order>();

// ---------------------------------------------------------------------------
// Side-channel for capturing the email-verification token in the demo
// (a real app would deliver this via SMTP / SES / Postmark / etc.)
// ---------------------------------------------------------------------------

let capturedToken: string | null = null;

export const setCapturedToken = (token: string): void => {
  capturedToken = token;
};

export const consumeCapturedToken = (): string => {
  if (!capturedToken) {
    throw new Error("No verification token was captured");
  }
  const token = capturedToken;
  capturedToken = null;
  return token;
};

// ---------------------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------------------

export const findEmployeeByEmail = (email: string): Employee | undefined => {
  const normalized = email.trim().toLowerCase();
  for (const employee of employees.values()) {
    if (employee.email === normalized) return employee;
  }
  return undefined;
};

export const nextId = (prefix: string): string =>
  `${prefix}-${Math.random().toString(36).slice(2, 10)}`;

// ---------------------------------------------------------------------------
// Seed data
// ---------------------------------------------------------------------------

export const ADMIN_EMPLOYEE_ID = "emp-admin";

export const seedNorthwind = (): void => {
  employees.clear();
  passwords.clear();
  sessions.clear();
  userRoles.clear();
  emailVerifications.clear();
  rateLimits.clear();
  oauthStates.clear();
  oauthAccounts.clear();
  categories.clear();
  products.clear();
  customers.clear();
  orders.clear();

  employees.set(ADMIN_EMPLOYEE_ID, {
    id: ADMIN_EMPLOYEE_ID,
    email: "andrew.fuller@northwind.example",
    emailVerified: true,
    firstName: "Andrew",
    lastName: "Fuller",
    title: "Vice President, Sales",
    createdAt: new Date(),
    updatedAt: new Date(),
    attributes: {},
  });
  userRoles.set(ADMIN_EMPLOYEE_ID, ["Admin"]);

  categories.set("cat-beverages", {
    id: "cat-beverages",
    name: "Beverages",
    description: "Soft drinks, coffees, teas, beers, and ales",
  });
  categories.set("cat-produce", {
    id: "cat-produce",
    name: "Produce",
    description: "Dried fruit and bean curd",
  });

  products.set("prod-chai", {
    id: "prod-chai",
    name: "Chai",
    unitPrice: 18.0,
    unitsInStock: 39,
    categoryId: "cat-beverages",
    discontinued: false,
  });
  products.set("prod-chang", {
    id: "prod-chang",
    name: "Chang",
    unitPrice: 19.0,
    unitsInStock: 17,
    categoryId: "cat-beverages",
    discontinued: false,
  });
  products.set("prod-tofu", {
    id: "prod-tofu",
    name: "Tofu",
    unitPrice: 23.25,
    unitsInStock: 35,
    categoryId: "cat-produce",
    discontinued: false,
  });

  customers.set("cust-around-horn", {
    id: "cust-around-horn",
    companyName: "Around the Horn",
    contactName: "Thomas Hardy",
    phone: "(171) 555-7788",
    createdByEmployeeId: ADMIN_EMPLOYEE_ID,
  });
};
