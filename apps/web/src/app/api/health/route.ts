import { NextResponse } from "next/server";

export async function GET() {
  return NextResponse.json(
    {
      status: "ready",
      checked_at: new Date().toISOString(),
    },
    {
      headers: {
        "cache-control": "no-store",
      },
    },
  );
}
