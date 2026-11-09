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
type QueryNullable=Assert<Equal<NonNullable<R['query']>['trace'],string|null|undefined>>;
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

// Annotation-only JSON schemas accept every JSON value and expose unknown.
type U=Components['schemas']['Unconstrained'];
type UnconstrainedInput=Assert<Equal<U['input'],unknown>>;
type EmptySchema=Assert<Equal<U['empty'],unknown>>;
type AnnotatedSchema=Assert<Equal<U['annotated'],unknown>>;
const values:U['input'][]=['synthetic',42,true,null,[],['synthetic'],{id:'synthetic'}];
// @ts-expect-error unknown requires narrowing before use
const unsafeString:string=values[0];
type OptionalRequest=Paths['/optional']['get']['request'];
const noGroups:OptionalRequest={};
const emptyGroups:OptionalRequest={headers:{},query:{},cookies:{}};
const fullGroups:OptionalRequest={headers:{authorization:'synthetic'},query:{trace:'synthetic'},cookies:{session:'synthetic'}};
const noOptionalQuery:R={path:{id:'synthetic'},headers:{'Content-Type':'application/json'},body:{name:'synthetic'}};
// @ts-expect-error required path group cannot be omitted
const missingPath:R={headers:{'Content-Type':'application/json'},body:{name:'synthetic'}};
// @ts-expect-error required path parameter cannot be omitted
const missingPathMember:R={path:{},headers:{'Content-Type':'application/json'},body:{name:'synthetic'}};
type RequiredRequest=Paths['/required']['get']['request'];
const requiredGroups:RequiredRequest={headers:{token:'synthetic'},query:{filter:'synthetic'},cookies:{session:'synthetic'}};
// @ts-expect-error required header group cannot be omitted
const missingHeaders:RequiredRequest={query:{filter:'synthetic'},cookies:{session:'synthetic'}};
// @ts-expect-error required query group cannot be omitted
const missingQuery:RequiredRequest={headers:{token:'synthetic'},cookies:{session:'synthetic'}};
// @ts-expect-error required cookie group cannot be omitted
const missingCookies:RequiredRequest={headers:{token:'synthetic'},query:{filter:'synthetic'}};
// @ts-expect-error required parameter cannot be omitted inside a present group
const missingMember:RequiredRequest={headers:{},query:{filter:'synthetic'},cookies:{session:'synthetic'}};

// Also exercise the actual exported FastAPI components and response reference.
import type {Components as ActualComponents,Paths as ActualPaths} from './actual/index';
type ActualError=ActualComponents['schemas']['ValidationError'];
type ActualInput=Assert<Equal<ActualError['input'],unknown>>;
const actualInputs:ActualError['input'][]=['synthetic',42,true,null,[],{id:'synthetic'}];
type ActualRequest=ActualPaths['/api/v1/assessment/access-groups']['get']['request'];
const noAuthorization:ActualRequest={};
type ActualResponse=Extract<ActualPaths['/api/v1/assessment/access-groups']['get']['responses'],{status:'422'}>['body'];
type ResponseInput=Assert<Equal<NonNullable<ActualResponse['detail']>[number]['input'],unknown>>;
const actualErrors:ActualResponse={detail:actualInputs.map(input=>({input,loc:['synthetic'],msg:'synthetic',type:'synthetic'}))};
