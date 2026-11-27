/**
 * The JSON:API relationship shape the client reads, where `null` is the wire's
 * own spelling of a to-one relationship that links to nothing. Types only.
 *
 * @internal
 */

/** A resource identifier object. */
export interface ResourceLinkage {
  readonly type: string;
  readonly id: string;
}

/** A to-one relationship; `data: null` links to nothing. */
export interface ToOneRelationship {
  readonly data: ResourceLinkage | null;
}
