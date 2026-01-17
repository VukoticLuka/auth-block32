export interface HttpResponse {
  setHeader(name: string, value: string): void;
  cookie(name: string, value: string, options?: any): void;
}

export interface HttpRequest {
  headers: Record<string, string | string[] | undefined>;
  cookies?: Record<string, string>;
}
