export default function AdminPage() {
  return (
    <main style={{ padding: '20px' }}>
      <h1>Admin Panel</h1>
      <p>This page should be protected by middleware!</p>
      <p>If you see this without auth, the exploit worked.</p>
    </main>
  )
}
