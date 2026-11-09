import type {Components, Paths} from './generated/index';
type Equal<A,B>=(<T>()=>T extends A?1:2) extends (<T>()=>T extends B?1:2)?true:false;
type Assert<T extends true>=T;
type W=Components['schemas']['Widget'];
type Required=Assert<Equal<{} extends Pick<W,'id'>?true:false,false>>;
type Optional=Assert<Equal<W['optionalName'],string|undefined>>;
type Nullable=Assert<Equal<W['nullableRequired'],string|null>>;
type OptionalNullable=Assert<Equal<W['optionalNullable'],number|null|undefined>>;
type Union=Assert<Equal<W['selection'],string|number>>;
type Enum=Assert<Equal<W['status'],'open'|'closed'|undefined>>;
const valid:W={id:'synthetic',nullableRequired:null,selection:1};
// @ts-expect-error required identifier cannot be omitted
const missing:W={nullableRequired:null,selection:'a'};
// @ts-expect-error required nullable field may be null, not omitted
const missingNullable:W={id:'synthetic',selection:1};
// @ts-expect-error unrelated union member is invalid
const invalidUnion:W={id:'synthetic',nullableRequired:null,selection:true};
type R=Paths['/widgets/{id}']['post']['request'];
type RequiredBody=Assert<Equal<{} extends Pick<R,'body'>?true:false,false>>;
type BodyName=Assert<Equal<R['body']['name'],string>>;
type PathId=Assert<Equal<R['path']['id'],string>>;
type QueryNullable=Assert<Equal<R['query']['trace'],string|null|undefined>>;
// @ts-expect-error required request name is enforced
const badBody:R['body']={reason:null};
type Responses=Paths['/inline']['post']['responses'];
type Status=Assert<Equal<Responses['status'],'201'|'400'|'422'>>;
type Success=Extract<Responses,{status:'201'}>['body'];
type Error=Extract<Responses,{status:'400'}>['body'];
type Validation=Extract<Responses,{status:'422'}>['body'];
type SuccessId=Assert<Equal<Success['id'],string>>;
type ErrorCode=Assert<Equal<Error['code'],'invalid'>>;
type ValidationDetails=Assert<Equal<Validation['details'],string[]>>;
// @ts-expect-error error response cannot be replaced by a success payload
const wrongError:Error={id:'synthetic'};
// @ts-expect-error error code stays constrained
const wrongCode:Error={code:'arbitrary',message:'synthetic'};
type Combined=Components['schemas']['Merged'];
const both:Combined={a:'synthetic',b:1};
// @ts-expect-error allOf requires both members
const half:Combined={a:'synthetic'};
