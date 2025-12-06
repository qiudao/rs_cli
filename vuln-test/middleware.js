import { NextResponse } from 'next/server'

export function middleware(request) {
  // Simple auth middleware (will be bypassed)
  const authHeader = request.headers.get('authorization')

  if (!authHeader) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  return NextResponse.next()
}

export const config = {
  matcher: ['/api/:path*', '/admin/:path*']
}
