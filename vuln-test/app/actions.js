'use server'

export async function submitForm(formData) {
  const name = formData.get('name')
  return { message: `Hello, ${name}!` }
}

export async function getData() {
  return { timestamp: Date.now() }
}
