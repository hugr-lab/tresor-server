// The secret types DuckDB knows (core extensions, DuckLake, mssql) and their providers' parameters: what a new
// secret's form starts with. Data in secret-types.json, gathered from the extensions' documentation and sources.
import catalogue from './secret-types.json'

export interface TemplateParam {
  name: string
  type: string
  secret: boolean
  required: boolean
  description: string
  example?: string
  common?: boolean // prefilled in a new secret's form (with the required ones)
}

export interface ProviderTemplate {
  provider: string
  description: string
  params: TemplateParam[]
}

export interface TypeTemplate {
  type: string
  extension: string
  description: string
  scope?: string
  docs?: string
  providers: ProviderTemplate[]
}

export const templates: TypeTemplate[] = (catalogue as { types: TypeTemplate[] }).types

export const templateOf = (type: string) => templates.find((t) => t.type.toLowerCase() === type.toLowerCase())

/** a type's and provider's parameters, all of them (the form starts with the required and common ones) */
export const paramsOf = (type: string, provider: string) => templateOf(type)?.providers.find((p) => p.provider === provider)?.params ?? []
