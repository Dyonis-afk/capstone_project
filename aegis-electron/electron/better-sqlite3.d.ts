// Type definitions for better-sqlite3
// These supplement the @types/better-sqlite3 package

declare module 'better-sqlite3' {
    interface Database {
        pragma(pragma: string, options?: { simple?: boolean }): any;
        exec(sql: string): this;
        prepare<T = any>(sql: string): Statement<T>;
        close(): void;
    }

    interface Statement<T = any> {
        run(...params: any[]): RunResult;
        get(...params: any[]): T | undefined;
        all(...params: any[]): T[];
        iterate(...params: any[]): IterableIterator<T>;
    }

    interface RunResult {
        changes: number;
        lastInsertRowid: number | bigint;
    }

    interface Options {
        readonly?: boolean;
        fileMustExist?: boolean;
        timeout?: number;
        verbose?: (message: string) => void;
    }

    function Database(filename: string, options?: Options): Database;

    export = Database;
}