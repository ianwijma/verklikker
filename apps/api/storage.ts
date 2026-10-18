import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  HeadBucketCommand,
  DeleteObjectCommand,
  CreateBucketCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { createReadStream, createWriteStream } from "node:fs";
import { pipeline } from "node:stream/promises";
import { Readable } from "node:stream";
export class Storage {
  readonly client: S3Client;
  readonly signer: S3Client;
  constructor(
    readonly bucket: string,
    endpoint?: string,
    publicEndpoint = process.env.S3_PUBLIC_ENDPOINT,
  ) {
    const config = {
      region: process.env.AWS_REGION ?? "us-east-1",
      forcePathStyle: !!endpoint,
      requestChecksumCalculation: "WHEN_REQUIRED" as const,
      responseChecksumValidation: "WHEN_REQUIRED" as const,
    };
    this.client = new S3Client({ ...config, endpoint });
    this.signer = publicEndpoint
      ? new S3Client({ ...config, endpoint: publicEndpoint })
      : this.client;
  }
  async init() {
    try {
      await this.client.send(new HeadBucketCommand({ Bucket: this.bucket }));
      return;
    } catch (e: any) {
      if (e.$metadata?.httpStatusCode !== 404) throw e;
    }
    try {
      await this.client.send(new CreateBucketCommand({ Bucket: this.bucket }));
    } catch (e: any) {
      if (!["BucketAlreadyExists", "BucketAlreadyOwnedByYou"].includes(e.name))
        throw e;
    }
  }
  putURL(key: string, size: number, mediaType: string) {
    return getSignedUrl(
      this.signer,
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        ContentLength: size,
        ContentType: mediaType,
      }),
      { expiresIn: 900 },
    );
  }
  getURL(key: string, name: string) {
    return getSignedUrl(
      this.signer,
      new GetObjectCommand({
        Bucket: this.bucket,
        Key: key,
        ResponseContentDisposition: `attachment; filename*=UTF-8''${encodeURIComponent(name.replace(/[\r\n]/g, ""))}`,
      }),
      { expiresIn: 900 },
    );
  }
  async head(key: string) {
    return this.client.send(
      new HeadObjectCommand({ Bucket: this.bucket, Key: key }),
    );
  }
  async put(key: string, data: Buffer, type: string) {
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: data,
        ContentType: type,
      }),
    );
  }
  async bytes(key: string) {
    const o = await this.client.send(
      new GetObjectCommand({ Bucket: this.bucket, Key: key }),
    );
    return Buffer.from(await o.Body!.transformToByteArray());
  }
  async download(key: string, path: string) {
    const o = await this.client.send(
      new GetObjectCommand({ Bucket: this.bucket, Key: key }),
    );
    await pipeline(
      o.Body as Readable,
      createWriteStream(path, { mode: 0o600, flags: "wx" }),
    );
  }
  async delete(key: string) {
    await this.client.send(
      new DeleteObjectCommand({ Bucket: this.bucket, Key: key }),
    );
  }
}
