// purpose: DynamoDB-backed CacheAdapter using DynamoDBDocumentClient + native TTL attribute.

import { DynamoDBClient, ResourceNotFoundException } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  DeleteCommand,
} from '@aws-sdk/lib-dynamodb';
import { ConditionalCheckFailedException } from '@aws-sdk/client-dynamodb';
import type { CacheAdapter } from './types.js';

export interface DynamoCacheOptions {
  tableName: string;
  region: string;
  endpoint?: string;
}

interface StoredItem {
  key: string;
  value: string;
  ttl: number;
}

export class DynamoCache implements CacheAdapter {
  private readonly tableName: string;
  private readonly doc: DynamoDBDocumentClient;

  constructor(options: DynamoCacheOptions) {
    this.tableName = options.tableName;
    const client = new DynamoDBClient({
      region: options.region,
      ...(options.endpoint ? { endpoint: options.endpoint } : {}),
    });
    this.doc = DynamoDBDocumentClient.from(client);
  }

  async get<T>(key: string): Promise<T | null> {
    try {
      const result = await this.doc.send(
        new GetCommand({ TableName: this.tableName, Key: { key } }),
      );
      const item = result.Item as StoredItem | undefined;
      if (!item) return null;
      // DDB's TTL sweep lags up to 48h; guard against stale reads.
      if (item.ttl <= Math.floor(Date.now() / 1000)) return null;
      return JSON.parse(item.value) as T;
    } catch (err) {
      if (err instanceof ResourceNotFoundException) return null;
      throw err;
    }
  }

  async set<T>(key: string, value: T, ttlSeconds: number): Promise<void> {
    const item: StoredItem = {
      key,
      value: JSON.stringify(value),
      ttl: Math.floor(Date.now() / 1000) + ttlSeconds,
    };
    try {
      await this.doc.send(new PutCommand({ TableName: this.tableName, Item: item }));
    } catch (err) {
      if (err instanceof ConditionalCheckFailedException) return;
      throw err;
    }
  }

  async delete(key: string): Promise<void> {
    await this.doc.send(new DeleteCommand({ TableName: this.tableName, Key: { key } }));
  }
}
