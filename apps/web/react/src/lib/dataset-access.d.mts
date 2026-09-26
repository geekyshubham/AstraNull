import type { PortalDataset, Session } from './types';

type DatasetAccessSession = Pick<Session, 'principal' | 'role' | 'staff_role'> | null | undefined;

export declare const CUSTOMER_DATASET_PERMISSIONS: Readonly<Partial<Record<PortalDataset, string>>>;

export declare const STAFF_DATASET_PERMISSIONS: Readonly<Partial<Record<PortalDataset, string>>>;

export declare function canReadDataset(session: DatasetAccessSession, dataset: PortalDataset): boolean;

export declare function sessionHasPermission(session: DatasetAccessSession, permission: string): boolean;

export declare function staffSessionHasPermission(session: DatasetAccessSession, permission: string): boolean;
