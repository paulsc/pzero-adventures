(function(){"use strict";var t={2807:function(t,e,i){var s=i(9242),a=i(3396);const o={id:"app"};function n(t,e,i,s,n,f){const r=(0,a.up)("the-canvas");return(0,a.wg)(),(0,a.iD)("div",o,[(0,a.Wm)(r)])}var f=i(7139);const r=t=>((0,a.dD)("data-v-7f999e54"),t=t(),(0,a.Cn)(),t),c={class:"game-canvas"},h={key:0,class:"game-message"},g={key:0,class:"game-message-container"},d=r((()=>(0,a._)("div",null,"Enter your name and submit to the highscore:",-1))),I={key:1,class:"game-message-container"},_={class:"highscore-table"},m=r((()=>(0,a._)("tr",null,[(0,a._)("th",{colspan:"3",style:{padding:"12px"}},"HIGH SCORES")],-1))),D=r((()=>(0,a._)("tr",null,[(0,a._)("th",{style:{width:"80px"}},"RANK"),(0,a._)("th",{style:{width:"240px"}},"SCORE"),(0,a._)("th",{style:{width:"120px"}},"NAME")],-1))),l={style:{"padding-top":"24px"}};function Y(t,e,i,o,n,r){const Y=(0,a.up)("canvas-tile"),u=(0,a.up)("score-display");return(0,a.wg)(),(0,a.iD)("div",c,[(0,a._)("div",{class:"game-layer",style:(0,f.j5)({left:`-${t.displacement}px`})},[((0,a.wg)(!0),(0,a.iD)(a.HY,null,(0,a.Ko)(t.tiles,((t,e)=>((0,a.wg)(),(0,a.iD)("div",{key:`tile-${e}`},[(0,a.Wm)(Y,{"sprite-offset-x":t.spriteOffsetX,"sprite-offset-y":t.spriteOffsetY,width:t.imageWidth,height:t.imageHeight,x:t.x,y:t.y,z:t.z},null,8,["sprite-offset-x","sprite-offset-y","width","height","x","y","z"])])))),128))],4),(0,a.Wm)(u,{value:t.tick},null,8,["value"]),t.stage!==t.STAGE.PLAYING?((0,a.wg)(),(0,a.iD)("div",h,[t.stage===t.STAGE.AWAITING_HIGHSCORE?((0,a.wg)(),(0,a.iD)("div",g,[(0,a._)("form",{onSubmit:e[1]||(e[1]=(...e)=>t.alert&&t.alert(...e))},[(0,a._)("div",null,"You scored "+(0,f.zw)(t.tick)+" points!",1),d,(0,a._)("div",null,[(0,a.wy)((0,a._)("input",{placeholder:"Enter your name here",style:{"margin-top":"16px"},maxlength:"3","onUpdate:modelValue":e[0]||(e[0]=e=>t.name=e)},null,512),[[s.nr,t.name]])])],32)])):t.stage===t.STAGE.DISPLAYING_HIGHSCORE?((0,a.wg)(),(0,a.iD)("div",I,[(0,a._)("table",_,[m,D,((0,a.wg)(),(0,a.iD)(a.HY,null,(0,a.Ko)(10,(e=>(0,a._)("tr",{key:e},[(0,a._)("td",null,(0,f.zw)(e),1),(0,a._)("td",null,(0,f.zw)(t.scoreboard[e-1]?t.scoreboard[e-1].score.toString().padStart(5,"0"):"-"),1),(0,a._)("td",null,(0,f.zw)(t.scoreboard[e-1]?t.scoreboard[e-1].name:"-"),1)]))),64))]),(0,a._)("div",l,(0,f.zw)(t.finalMessage),1)])):(0,a.kq)("",!0)])):(0,a.kq)("",!0)])}var u=i(65);function G(t){return 40*t*(1+t/1200)}var N={namespaced:!0,state:{_tiles:[]},getters:{tiles(t,e,i){const s=[];return s.push(i.game.player,...t._tiles,...i.game.entities),s},displacement(t,e,i){return G(i.game.partialTick)}},mutations:{},actions:{},modules:{}},p={namespaced:!0,state:{pressedKeys:{}},getters:{},mutations:{},actions:{createKeyboardListeners({state:t}){window.addEventListener("keydown",(function(e){t.pressedKeys[e.key]=!0})),window.addEventListener("keyup",(function(e){t.pressedKeys[e.key]=!1}))}},modules:{}},X=i(6265),O=i.n(X),E=i(2482);i(6699);function k(t,e,i){return{left:e+t.offsetX,right:e+t.offsetX+t.width,top:i+t.offsetY,bottom:i+t.offsetY+t.height}}function w(t,e){const i=t.boundingBoxes,s=e.boundingBoxes;for(const a of i)for(const t of s)if(!(a.right<t.left)&&!(t.right<a.left)&&!(a.bottom<t.top)&&!(t.bottom<a.top))return!0;return!1}function y(t){return class{constructor(e,i){(0,E.Z)(this,"_x",void 0),(0,E.Z)(this,"_y",void 0),(0,E.Z)(this,"_action",void 0),(0,E.Z)(this,"hitboxesMap",void 0),this._x=e,this._y=i,this._action="IDLE",this.hitboxesMap=t}setAction(t,e){this._action=e}setX(t){this._x=t}setY(t){this._y=t}isCollide(t){return w(this,t)}get action(){return this._action}get x(){return this._x}get y(){return this._y}get boundingBoxes(){return this.hitboxesMap[this._action].map((t=>k(t,this.x,this.y)))}}}const H=y({IDLE:[{offsetX:0,offsetY:0,width:57,height:63}],MOVING_1:[{offsetX:0,offsetY:0,width:57,height:63}],MOVING_2:[{offsetX:0,offsetY:0,width:57,height:63}],JUMP:[{offsetX:0,offsetY:0,width:57,height:63}],ATTACK_1:[{offsetX:0,offsetY:0,width:168,height:63}],DYING_1:[],DYING_2:[],DYING_3:[],DYING_4:[],DYING_5:[],DIED:[]}),M=y({IDLE:[{offsetX:0,offsetY:0,width:27,height:51}],DYING_1:[],DYING_2:[],DYING_3:[],DYING_4:[],DYING_5:[],DIED:[]}),v=y({IDLE:[{offsetX:0,offsetY:0,width:27,height:75}],DYING_1:[],DYING_2:[],DYING_3:[],DYING_4:[],DYING_5:[],DIED:[]}),W=y({IDLE:[{offsetX:0,offsetY:0,width:27,height:51}],DYING_1:[],DYING_2:[],DYING_3:[],DYING_4:[],DYING_5:[],DIED:[]}),T=y({IDLE:[{offsetX:0,offsetY:0,width:24,height:24}],MOVING_1:[{offsetX:0,offsetY:0,width:24,height:24}],MOVING_2:[{offsetX:0,offsetY:0,width:24,height:24}],DYING_1:[],DYING_2:[],DYING_3:[],DYING_4:[],DYING_5:[],DYING_6:[],DIED:[]}),b=y({IDLE:[{offsetX:0,offsetY:0,width:24,height:24}],MOVING_1:[{offsetX:0,offsetY:0,width:24,height:24}],MOVING_2:[{offsetX:0,offsetY:0,width:24,height:24}],DYING_1:[],DYING_2:[],DYING_3:[],DYING_4:[],DYING_5:[],DYING_6:[],DIED:[]}),x=y({IDLE:[{offsetX:0,offsetY:0,width:24,height:24}],MOVING_1:[{offsetX:0,offsetY:0,width:24,height:24}],MOVING_2:[{offsetX:0,offsetY:0,width:24,height:24}],DYING_1:[],DYING_2:[],DYING_3:[],DYING_4:[],DYING_5:[],DYING_6:[],DIED:[]}),L=y({IDLE:[{offsetX:0,offsetY:0,width:24,height:24}],MOVING_1:[{offsetX:0,offsetY:0,width:24,height:24}],MOVING_2:[{offsetX:0,offsetY:0,width:24,height:24}],DYING_1:[],DYING_2:[],DYING_3:[],DYING_4:[],DYING_5:[],DYING_6:[],DIED:[]});function V(t){return class{constructor(t,e,i){(0,E.Z)(this,"_x",void 0),(0,E.Z)(this,"_y",void 0),(0,E.Z)(this,"_z",void 0),(0,E.Z)(this,"action",void 0),this._x=t,this._y=e,this._z=i,this.action="IDLE"}setAction(t,e){this.action=e}get spriteOffsetX(){return t[this.action].offsetX}get spriteOffsetY(){return t[this.action].offsetY}get imageWidth(){return t[this.action].imageWidth}get imageHeight(){return t[this.action].imageHeight}setX(t){this._x=t}setY(t){this._y=t}get x(){return this._x}get y(){return this._y}get z(){return this._z}}}V({IDLE:{offsetX:0,offsetY:860,imageWidth:216,imageHeight:24}});const A=V({IDLE:{offsetX:0,offsetY:908,imageWidth:600,imageHeight:24}}),S=V({IDLE:{offsetX:0,offsetY:932,imageWidth:600,imageHeight:24}}),C=(V({IDLE:{offsetX:0,offsetY:956,imageWidth:600,imageHeight:24}}),V({IDLE:{offsetX:0,offsetY:980,imageWidth:600,imageHeight:24}}),V({IDLE:{offsetX:0,offsetY:500,imageWidth:51,imageHeight:75}})),P=V({IDLE:{offsetX:408,offsetY:500,imageWidth:171,imageHeight:387}}),Z=V({IDLE:{offsetX:96,offsetY:500,imageWidth:123,imageHeight:315}}),z=V({IDLE:{offsetX:240,offsetY:500,imageWidth:147,imageHeight:363}}),B=V({IDLE:{offsetX:600,offsetY:500,imageWidth:123,imageHeight:411}}),K=V({IDLE:{offsetX:744,offsetY:500,imageWidth:219,imageHeight:483}}),U=V({IDLE:{offsetX:0,offsetY:596,imageWidth:75,imageHeight:147}}),j=V({IDLE:{offsetX:0,offsetY:0,imageWidth:57,imageHeight:63},MOVING_1:{offsetX:60,offsetY:0,imageWidth:57,imageHeight:63},MOVING_2:{offsetX:120,offsetY:0,imageWidth:57,imageHeight:63},JUMP:{offsetX:180,offsetY:0,imageWidth:57,imageHeight:63},ATTACK_1:{offsetX:300,offsetY:0,imageWidth:168,imageHeight:63},DYING_1:{offsetX:240,offsetY:0,imageWidth:57,imageHeight:63},DYING_2:{offsetX:240,offsetY:0,imageWidth:57,imageHeight:63},DYING_3:{offsetX:240,offsetY:0,imageWidth:57,imageHeight:63},DYING_4:{offsetX:240,offsetY:0,imageWidth:57,imageHeight:63},DYING_5:{offsetX:240,offsetY:0,imageWidth:57,imageHeight:63},DIED:{offsetX:240,offsetY:0,imageWidth:57,imageHeight:63}}),$=V({IDLE:{offsetX:0,offsetY:764,imageWidth:27,imageHeight:51}}),R=V({IDLE:{offsetX:624,offsetY:932,imageWidth:27,imageHeight:75}}),q=V({IDLE:{offsetX:672,offsetY:932,imageWidth:57,imageHeight:75}}),J=V({IDLE:{offsetX:0,offsetY:90,imageWidth:36,imageHeight:30},MOVING_1:{offsetX:0,offsetY:90,imageWidth:36,imageHeight:30},MOVING_2:{offsetX:45,offsetY:90,imageWidth:36,imageHeight:30},DYING_1:{offsetX:0,offsetY:180,imageWidth:33,imageHeight:90},DYING_2:{offsetX:40,offsetY:180,imageWidth:33,imageHeight:90},DYING_3:{offsetX:80,offsetY:180,imageWidth:33,imageHeight:90},DYING_4:{offsetX:120,offsetY:180,imageWidth:33,imageHeight:90},DYING_5:{offsetX:160,offsetY:180,imageWidth:33,imageHeight:90},DYING_6:{offsetX:200,offsetY:180,imageWidth:33,imageHeight:90},DIED:{offsetX:200,offsetY:180,imageWidth:33,imageHeight:90}}),F=V({IDLE:{offsetX:90,offsetY:90,imageWidth:42,imageHeight:21},MOVING_1:{offsetX:90,offsetY:90,imageWidth:42,imageHeight:21},MOVING_2:{offsetX:135,offsetY:90,imageWidth:42,imageHeight:21},DYING_1:{offsetX:0,offsetY:180,imageWidth:33,imageHeight:90},DYING_2:{offsetX:40,offsetY:180,imageWidth:33,imageHeight:90},DYING_3:{offsetX:80,offsetY:180,imageWidth:33,imageHeight:90},DYING_4:{offsetX:120,offsetY:180,imageWidth:33,imageHeight:90},DYING_5:{offsetX:160,offsetY:180,imageWidth:33,imageHeight:90},DYING_6:{offsetX:200,offsetY:180,imageWidth:33,imageHeight:90},DIED:{offsetX:200,offsetY:180,imageWidth:33,imageHeight:90}}),Q=V({IDLE:{offsetX:180,offsetY:90,imageWidth:45,imageHeight:24},MOVING_1:{offsetX:180,offsetY:90,imageWidth:45,imageHeight:24},MOVING_2:{offsetX:225,offsetY:90,imageWidth:45,imageHeight:24},DYING_1:{offsetX:0,offsetY:180,imageWidth:33,imageHeight:90},DYING_2:{offsetX:40,offsetY:180,imageWidth:33,imageHeight:90},DYING_3:{offsetX:80,offsetY:180,imageWidth:33,imageHeight:90},DYING_4:{offsetX:120,offsetY:180,imageWidth:33,imageHeight:90},DYING_5:{offsetX:160,offsetY:180,imageWidth:33,imageHeight:90},DYING_6:{offsetX:200,offsetY:180,imageWidth:33,imageHeight:90},DIED:{offsetX:200,offsetY:180,imageWidth:33,imageHeight:90}}),tt=V({IDLE:{offsetX:270,offsetY:90,imageWidth:42,imageHeight:30},MOVING_1:{offsetX:270,offsetY:90,imageWidth:42,imageHeight:30},MOVING_2:{offsetX:315,offsetY:90,imageWidth:42,imageHeight:30},DYING_1:{offsetX:0,offsetY:180,imageWidth:33,imageHeight:90},DYING_2:{offsetX:40,offsetY:180,imageWidth:33,imageHeight:90},DYING_3:{offsetX:80,offsetY:180,imageWidth:33,imageHeight:90},DYING_4:{offsetX:120,offsetY:180,imageWidth:33,imageHeight:90},DYING_5:{offsetX:160,offsetY:180,imageWidth:33,imageHeight:90},DYING_6:{offsetX:200,offsetY:180,imageWidth:33,imageHeight:90},DIED:{offsetX:200,offsetY:180,imageWidth:33,imageHeight:90}}),et=["IDLE","MOVING_1","MOVING_2"],it=["IDLE","MOVING_1","MOVING_2"],st=["IDLE","MOVING_1","MOVING_2","JUMP","ATTACK_1"];function at(t,e,i,s){return class{constructor(s,a,o,n){(0,E.Z)(this,"_id",void 0),(0,E.Z)(this,"_name",void 0),(0,E.Z)(this,"physicalObject",void 0),(0,E.Z)(this,"tile",void 0),(0,E.Z)(this,"_action",void 0),(0,E.Z)(this,"_actionStartedTick",void 0),(0,E.Z)(this,"_x",void 0),(0,E.Z)(this,"_y",void 0),this._id=s,this._name=t,this._x=a,this._y=o,this.physicalObject=new e(a,o),this.tile=new i(a,o,n),this._action="IDLE",this._actionStartedTick=0}next(t,e){const{action:i,ticks:a}=s[this.action];this.actionStartedTick+a<=t&&this.setAction(t,i),st.includes(this._action)&&e.includes("DYING_1")&&this.setAction(t,"DYING_1"),et.includes(this._action)&&e.includes("JUMP")&&this.setAction(t,"JUMP"),it.includes(this._action)&&e.includes("ATTACK_1")&&this.setAction(t,"ATTACK_1")}setAction(t,e){this._action=e,this._actionStartedTick=t,this.physicalObject.setAction(t,e),this.tile.setAction(t,e)}setX(t){this._x=t,this.tile.setX(t),this.physicalObject.setX(t)}setY(t){this._y=t,this.tile.setY(t),this.physicalObject.setY(t)}get id(){return this._id}get name(){return this._name}get action(){return this._action}get actionStartedTick(){return this._actionStartedTick}get spriteOffsetX(){return this.tile.spriteOffsetX}get spriteOffsetY(){return this.tile.spriteOffsetY}get imageWidth(){return this.tile.imageWidth}get imageHeight(){return this.tile.imageHeight}get x(){return this._x}get y(){return this._y}get z(){return this.tile.z}isCollide(t){return this.physicalObject.isCollide(t)}get boundingBoxes(){return this.physicalObject.boundingBoxes}}}const ot=at("PLAYER",H,j,{IDLE:{action:"MOVING_1",ticks:1},MOVING_1:{action:"MOVING_2",ticks:3},MOVING_2:{action:"MOVING_1",ticks:3},JUMP:{action:"MOVING_1",ticks:5},ATTACK_1:{action:"MOVING_1",ticks:5},DYING_1:{action:"DIED",ticks:5},DIED:{action:"DIED",ticks:1}}),nt=at("OBSTACLE",M,$,{IDLE:{action:"IDLE",ticks:1}}),ft=at("OBSTACLE",v,R,{IDLE:{action:"IDLE",ticks:1}}),rt=at("OBSTACLE",W,q,{IDLE:{action:"IDLE",ticks:1}}),ct=at("BUG",T,J,{IDLE:{action:"MOVING_1",ticks:1},MOVING_1:{action:"MOVING_2",ticks:3},MOVING_2:{action:"MOVING_1",ticks:3},DYING_1:{action:"DYING_2",ticks:2},DYING_2:{action:"DYING_3",ticks:2},DYING_3:{action:"DYING_4",ticks:2},DYING_4:{action:"DYING_5",ticks:1},DYING_5:{action:"DYING_6",ticks:1},DYING_6:{action:"DIED",ticks:1},DIED:{action:"DIED",ticks:1}}),ht=at("BUG",b,F,{IDLE:{action:"MOVING_1",ticks:1},MOVING_1:{action:"MOVING_2",ticks:3},MOVING_2:{action:"MOVING_1",ticks:3},DYING_1:{action:"DYING_2",ticks:2},DYING_2:{action:"DYING_3",ticks:2},DYING_3:{action:"DYING_4",ticks:2},DYING_4:{action:"DYING_5",ticks:1},DYING_5:{action:"DYING_6",ticks:1},DYING_6:{action:"DIED",ticks:1},DIED:{action:"DIED",ticks:1}}),gt=at("BUG",x,Q,{IDLE:{action:"MOVING_1",ticks:1},MOVING_1:{action:"MOVING_2",ticks:3},MOVING_2:{action:"MOVING_1",ticks:3},DYING_1:{action:"DYING_2",ticks:2},DYING_2:{action:"DYING_3",ticks:2},DYING_3:{action:"DYING_4",ticks:2},DYING_4:{action:"DYING_5",ticks:1},DYING_5:{action:"DYING_6",ticks:1},DYING_6:{action:"DIED",ticks:1},DIED:{action:"DIED",ticks:1}}),dt=at("BUG",L,tt,{IDLE:{action:"MOVING_1",ticks:1},MOVING_1:{action:"MOVING_2",ticks:3},MOVING_2:{action:"MOVING_1",ticks:3},DYING_1:{action:"DYING_2",ticks:2},DYING_2:{action:"DYING_3",ticks:2},DYING_3:{action:"DYING_4",ticks:2},DYING_4:{action:"DYING_5",ticks:1},DYING_5:{action:"DYING_6",ticks:1},DYING_6:{action:"DIED",ticks:1},DIED:{action:"DIED",ticks:1}}),It=10,_t=150,mt=27,Dt={PLAYING:1,AWAITING_HIGHSCORE:2,DISPLAYING_HIGHSCORE:3};function lt(t,e){let i=0;if("JUMP"===e.action){const s=t-e.actionStartedTick;i=150*(1-Math.pow((s-2.5)/2.5,2))}return{x:G(t)+_t,y:i+mt}}function Yt(t){const e=[];return t.ArrowUp?e.push("JUMP"):t[" "]&&e.push("ATTACK_1"),e}function ut(t){const e=Math.floor(2*Math.random()),i=mt-8;switch(e){case 0:return new S(t,i,1);default:return new A(t,i,1)}}function Gt(t){const e=Math.floor(7*Math.random()),i=24*(Math.floor(8*Math.random())+2),s=t+i,a=mt+8;switch(e){case 0:return new C(s,a,1);case 1:return new P(s,a,1);case 2:return new Z(s,a,1);case 3:return new z(s,a,1);case 4:return new B(s,a,1);case 5:return new K(s,a,1);default:return new U(s,a,1)}}function Nt(t,e){const i=24*Math.floor(10*Math.random()+5),s=e+i,a=24*Math.floor(5*Math.random()+2)+mt,o=mt,n=Math.floor(8*Math.random());if(n<5){const e=Math.floor(4*Math.random());switch(e){case 0:return new ct(t,s,a,4);case 1:return new ht(t,s,o,4);case 2:return new gt(t,s,o,4);default:return new dt(t,s,o,4)}}else{const e=Math.floor(3*Math.random());switch(e){case 0:return new nt(t,s,o,4);case 1:return new ft(t,s,o,4);default:return new rt(t,s,o,4)}}}var pt={namespaced:!0,state:{player:new ot(0,_t,mt,3),entities:[],startTimestamp:null,tick:0,lastProcessedTick:0,lastBuildingOffsetX:0,lastGroundOffsetX:0,lastCloudOffsetX:0,lastOpponentOffsetX:476,entitiesSpawned:1,scoreboard:[],finalMessage:"",stage:Dt.PLAYING},getters:{},mutations:{},actions:{start({state:t,getters:e,dispatch:i}){i("createTilesAndEntities"),setTimeout((()=>{t.startTimestamp=(new Date).getTime(),t.intervalFn=setInterval((()=>{i("processPartialTick")}),1e3/60)}),1e3)},stop({state:t,getters:e,dispatch:i}){clearInterval(t.intervalFn),t.stage=Dt.AWAITING_HIGHSCORE},async submitHighscore({state:t,getters:e,dispatch:i},s){try{const e=s.toUpperCase();console.log(`Submitting highscore using ${e} (${t.tick})`);const{data:{signature:a}}=await O().post("/api/sign",{name:e,score:t.tick}),{data:{message:o}}=await O().post("/api/highscores",{name:e,score:t.tick,signature:a});await i("getScoreboard"),t.stage=Dt.DISPLAYING_HIGHSCORE,t.finalMessage=o}catch(a){console.error({err:a})}},createTilesAndEntities({state:t,rootState:e}){const i=G(t.tick),s=1500;while(t.lastGroundOffsetX<i+s){const i=t.lastGroundOffsetX,s=ut(i);e.canvas._tiles.push(s),t.lastGroundOffsetX=s.x+s.imageWidth}while(t.lastBuildingOffsetX<i+s){const i=t.lastBuildingOffsetX,s=Gt(i);e.canvas._tiles.push(s),t.lastBuildingOffsetX=s.x+144}while(t.lastOpponentOffsetX<i+s){const e=t.lastOpponentOffsetX,i=Nt(t.entitiesSpawned,e);t.entities.push(i),t.lastOpponentOffsetX=i.x+96,t.entitiesSpawned+=1}},clearTilesAndEntities({state:t,rootState:e}){const i=G(t.tick),s=e.canvas._tiles;e.canvas._tiles=s.filter((t=>t.x+t.imageWidth>i));const a=t.entities;t.entities=a.filter((t=>t.x+1024>i)).filter((t=>"DIED"!==t.action))},processPartialTick({state:t,getters:e,dispatch:i}){const s=(new Date).getTime();t.partialTick=(s-t.startTimestamp)/1e3*It,t.tick=Math.floor(t.partialTick),t.tick!==t.lastProcessedTick&&(i("processTick"),t.lastProcessedTick=t.tick);const{x:a,y:o}=lt(t.partialTick,t.player);t.player.setX(a),t.player.setY(o)},processTick({state:t,getters:e,dispatch:i,rootState:s}){console.debug(`Processing tick ${t.tick}`);const a=t.player,o=t.entities,n=Yt(s.controller.pressedKeys),f={};o.forEach((t=>{f[t.id]=[]}));const r=o.filter((t=>a.isCollide(t))),c=r.filter((t=>"BUG"===t.name)),h=r.filter((t=>"OBSTACLE"===t.name));let g=!1;h.length>0&&(g=!0),c.length>0&&("ATTACK_1"===a.action?c.forEach((t=>{f[t.id].push("DYING_1")})):g=!0),a.next(t.tick,n),o.forEach((e=>e.next(t.tick,f[e.id]??[]))),i("createTilesAndEntities"),i("clearTilesAndEntities"),g&&i("stop")},async getScoreboard({state:t}){const{data:e}=await O().get("/api/highscores");t.scoreboard=e}},modules:{}},Xt=(0,u.MT)({state:{},getters:{},mutations:{},actions:{},modules:{canvas:N,controller:p,game:pt}});function Ot(t,e,i,s,o,n){return(0,a.wg)(),(0,a.iD)("div",{class:"entity-base",style:(0,f.j5)({width:`${t.width}px`,height:`${t.height}px`,left:`${t.x}px`,bottom:`${t.y}px`,zIndex:t.z,backgroundPosition:`-${t.spriteOffsetX}px -${t.spriteOffsetY}px`})},null,4)}var Et=(0,a.aZ)({name:"CanvasTile",props:{spriteOffsetX:{type:Number,required:!0},spriteOffsetY:{type:Number,required:!0},width:{type:Number,required:!0},height:{type:Number,required:!0},x:{type:Number,required:!0},y:{type:Number,required:!0},z:{type:Number,default:0}}}),kt=i(89);const wt=(0,kt.Z)(Et,[["render",Ot],["__scopeId","data-v-609275ce"]]);var yt=wt;const Ht={class:"score-display"};function Mt(t,e,i,s,o,n){return(0,a.wg)(),(0,a.iD)("div",Ht,(0,f.zw)(t.paddedValue),1)}var vt=(0,a.aZ)({name:"ScoreDisplay",props:{value:{type:Number,required:!0}},computed:{paddedValue(){return this.value.toString().padStart(5,"0")}}});const Wt=(0,kt.Z)(vt,[["render",Mt],["__scopeId","data-v-45a8ba0f"]]);var Tt=Wt,bt=(0,a.aZ)({name:"TheCanvas",components:{CanvasTile:yt,ScoreDisplay:Tt},props:{msg:String},computed:{...(0,u.Se)("canvas",["displacement","tiles"]),...(0,u.rn)("game",["tick","stage","scoreboard","finalMessage"])},data(){return{STAGE:Dt,name:""}},methods:{alert(t){t.preventDefault(),Xt.dispatch("game/submitHighscore",this.name)}}});const xt=(0,kt.Z)(bt,[["render",Y],["__scopeId","data-v-7f999e54"]]);var Lt=xt,Vt=(0,a.aZ)({name:"App",components:{TheCanvas:Lt},created(){Xt.dispatch("controller/createKeyboardListeners"),Xt.dispatch("game/start")}});const At=(0,kt.Z)(Vt,[["render",n]]);var St=At;(0,s.ri)(St).use(Xt).mount("#app")}},e={};function i(s){var a=e[s];if(void 0!==a)return a.exports;var o=e[s]={exports:{}};return t[s](o,o.exports,i),o.exports}i.m=t,function(){var t=[];i.O=function(e,s,a,o){if(!s){var n=1/0;for(h=0;h<t.length;h++){s=t[h][0],a=t[h][1],o=t[h][2];for(var f=!0,r=0;r<s.length;r++)(!1&o||n>=o)&&Object.keys(i.O).every((function(t){return i.O[t](s[r])}))?s.splice(r--,1):(f=!1,o<n&&(n=o));if(f){t.splice(h--,1);var c=a();void 0!==c&&(e=c)}}return e}o=o||0;for(var h=t.length;h>0&&t[h-1][2]>o;h--)t[h]=t[h-1];t[h]=[s,a,o]}}(),function(){i.n=function(t){var e=t&&t.__esModule?function(){return t["default"]}:function(){return t};return i.d(e,{a:e}),e}}(),function(){i.d=function(t,e){for(var s in e)i.o(e,s)&&!i.o(t,s)&&Object.defineProperty(t,s,{enumerable:!0,get:e[s]})}}(),function(){i.g=function(){if("object"===typeof globalThis)return globalThis;try{return this||new Function("return this")()}catch(t){if("object"===typeof window)return window}}()}(),function(){i.o=function(t,e){return Object.prototype.hasOwnProperty.call(t,e)}}(),function(){var t={826:0};i.O.j=function(e){return 0===t[e]};var e=function(e,s){var a,o,n=s[0],f=s[1],r=s[2],c=0;if(n.some((function(e){return 0!==t[e]}))){for(a in f)i.o(f,a)&&(i.m[a]=f[a]);if(r)var h=r(i)}for(e&&e(s);c<n.length;c++)o=n[c],i.o(t,o)&&t[o]&&t[o][0](),t[o]=0;return i.O(h)},s=self["webpackChunkarcade"]=self["webpackChunkarcade"]||[];s.forEach(e.bind(null,0)),s.push=e.bind(null,s.push.bind(s))}();var s=i.O(void 0,[998],(function(){return i(2807)}));s=i.O(s)})();