// Ported from browser-use/jev-ultrafast (MIT License, Copyright (c) 2026 Browser Use):
// jev_ultrafast/snapshot.js and the input/settle code in jev_ultrafast/browser.py.
// WebKit has no CDP, so input is synthesized with DOM events instead of Input.dispatch*.

import Foundation

/// JavaScript that runs in the private `agentKeychain` content world. Page scripts
/// share the DOM but cannot see `window.__agentKeychain` or tamper with it.
enum AgentPageScript {
    /// Installs the agent library once per document (idempotent) and binds it to `A`.
    /// Every call body is prefixed with this so a fresh navigation re-installs it.
    static let library = #"""
    const A = window.__agentKeychain ||= (() => {
      const cache = {ids:new WeakMap(), nodes:new Map(), next:1};
      const identity = e => {
        if (!cache.ids.has(e)) cache.ids.set(e,cache.next++);
        const id=cache.ids.get(e); cache.nodes.set(id,e); return id;
      };
      const safe = e => !['password','file','hidden'].includes(e.type);
      const visible = e => !e.closest('[aria-hidden="true"],[inert]') &&
        e.checkVisibility({checkOpacity:true,checkVisibilityCSS:true});
      const name = (e,seen=new Set()) => {
        if (!e || seen.has(e)) return '';
        seen.add(e);
        const referenced=(e.getAttribute('aria-labelledby')||'').split(/\s+/)
          .map(id=>name(document.getElementById(id),seen)).filter(Boolean).join(' ');
        return referenced || e.getAttribute('aria-label') ||
          [...(e.labels||[])].map(l=>name(l,seen)).filter(Boolean).join(' ') ||
          (['button','submit','reset'].includes(e.type) ? e.value : '') || e.getAttribute('alt') ||
          (e.tagName==='INPUT' ? '' : [...e.childNodes].map(n=>n.nodeType===3 ? n.textContent :
            n.nodeType===1 && n.getAttribute('aria-hidden')!=='true' ? name(n,seen) : '').join(' ').trim()) ||
          e.getAttribute('title') || e.getAttribute('placeholder') || '';
      };
      const roles=['button','link','checkbox','radio','switch','tab','menuitem','menuitemradio',
        'option','gridcell','combobox','textbox','searchbox','spinbutton'];
      const selector='a[href],button,input,textarea,select,summary,[contenteditable="true"],'+
        roles.map(role=>'[role="'+role+'"]').join(',');
      const role = e => {
        const explicit=e.getAttribute('role');
        if (roles.includes(explicit)) return explicit;
        if (e.tagName==='BUTTON' || e.tagName==='SUMMARY') return 'button';
        if (e.tagName==='A') return 'link';
        if (e.tagName==='SELECT') return 'combobox';
        if (e.tagName==='TEXTAREA' || e.isContentEditable) return 'textbox';
        if (e.tagName==='INPUT') {
          if (['checkbox','radio'].includes(e.type)) return e.type;
          if (['button','submit','reset','image'].includes(e.type)) return 'button';
          if (e.type==='search') return 'searchbox';
          if (e.type==='number') return 'spinbutton';
          if (['text','email','url','tel'].includes(e.type)) return 'textbox';
        }
        return null;
      };
      cache.pageKey=()=>[performance.timeOrigin,location.href,scrollX,scrollY,innerWidth,innerHeight,
        [...document.querySelectorAll('input,textarea,select')].filter(safe)
          .map(e=>[identity(e),e.value,e.checked,e.selectedIndex,e.disabled,e.readOnly])];
      cache.guard=e=>{
        if (!e?.isConnected || !visible(e)) return null;
        const scope=e.closest('form,dialog,[role="dialog"],article,li,tr,[role="row"]') || e.parentElement;
        return [identity(e),role(e),name(e),e.value??null,e.checked??null,e.selectedIndex??null,
          e.readOnly??null,e.matches(':disabled'),e.getAttribute('aria-disabled'),
          e.getAttribute('aria-expanded'),e.getAttribute('aria-checked'),e.getAttribute('aria-selected'),
          e.getAttribute('href'),scope?.innerText?.slice(0,6000)||''];
      };
      cache.nodeKey=node=>JSON.stringify([cache.pageKey(),cache.guard(cache.nodes.get(node))]);

      cache.snapshot=()=>{
        if (!document.body) return null;
        for (const [id,e] of cache.nodes) if (!e.isConnected) cache.nodes.delete(id);
        const actions=[];
        for (const e of document.querySelectorAll(selector)) {
          if (!safe(e) || !visible(e) || e.matches(':disabled') || e.closest('[aria-disabled="true"]')) continue;
          const r=e.getBoundingClientRect(), x=r.x+r.width/2, y=r.y+r.height/2, rname=role(e);
          if (!rname || r.width<=0 || r.height<=0 || x<0 || y<0 || x>=innerWidth || y>=innerHeight) continue;
          if (rname==='gridcell' && e.querySelector('button,[role="button"]')) continue;
          const base={node:identity(e),role:rname,label:name(e)||rname,
            rect:{x:r.x,y:r.y,w:r.width,h:r.height}};
          for (const key of ['checked','selected','expanded']) {
            const value=e.getAttribute('aria-'+key);
            if (value!==null) base[key]=value;
          }
          if (['checkbox','radio'].includes(e.type)) base.checked=String(e.checked);
          if (e.tagName==='SELECT') {
            for (const o of e.options) if (!o.selected && !o.disabled && !o.closest('optgroup[disabled]'))
              actions.push({...base,kind:'select',value:o.value,
                current_value:[...e.selectedOptions].map(o=>o.label).join(', '),label:base.label+' → '+o.label});
          } else {
            const editable=!e.readOnly && e.getAttribute('aria-readonly')!=='true' &&
              (['textbox','searchbox','spinbutton'].includes(rname) ||
                (rname==='combobox' && ['INPUT','TEXTAREA'].includes(e.tagName)));
            const value='value' in e ? String(e.value) :
              e.isContentEditable || rname==='combobox' ? e.innerText.trim() : '';
            actions.push({...base,kind:editable?'fill':'click',value});
            if (editable) actions.push({...base,kind:'click',value,label:'Open '+base.label});
          }
        }
        const words=[], walker=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);
        const range=document.createRange(); let node,length=0;
        while ((node=walker.nextNode()) && length<6000) {
          const value=node.textContent.trim(), parent=node.parentElement;
          if (!value || !parent || parent.closest('script,style,noscript,template') || !visible(parent)) continue;
          range.selectNodeContents(node); const r=range.getBoundingClientRect();
          if (r.width>0 && r.height>0 && r.bottom>0 && r.top<innerHeight && r.right>0 && r.left<innerWidth) {
            words.push(value); length+=value.length;
          }
        }
        const text=words.join('\n').slice(0,6000), height=document.documentElement.scrollHeight;
        const page_key=cache.pageKey(), node_keys={};
        for (const a of actions) if (!(a.node in node_keys))
          node_keys[a.node]=JSON.stringify([page_key,cache.guard(cache.nodes.get(a.node))]);
        // Compare meaning and identity. Geometry is always resolved and hit-tested just before input.
        const semantics=actions.map(({rect,...action})=>action);
        const marker=JSON.stringify([performance.timeOrigin,location.href,scrollX,scrollY,innerWidth,innerHeight,
          document.title,text,semantics,page_key[6]]);
        const omitted_actions=Math.max(0,actions.length-250);
        actions.splice(250);
        actions.forEach((a,i)=>a.id='e'+(i+1));
        if (scrollY+innerHeight<height-2) actions.push({id:'scroll_down',kind:'scroll',label:'Scroll down',delta:560});
        if (scrollY>0) actions.push({id:'scroll_up',kind:'scroll',label:'Scroll up',delta:-560});
        actions.push({id:'wait',kind:'wait',label:'Wait for the page to update'});
        const scroll={y:scrollY,height};
        return {url:location.href,title:document.title,text,actions,scroll,omitted_actions,
          marker,node_keys,fingerprint:JSON.stringify({url:location.href,text,actions,scroll})};
      };
      cache.marker=()=>cache.snapshot()?.marker ?? null;

      // Resolves an observed node for input: connected, enabled, visible, in the viewport and
      // not covered (hit test at its center). Node ids are code-owned, never model-generated selectors.
      const resolve=action=>{
        const e=cache.nodes.get(action.node);
        if (!e?.isConnected || e.matches(':disabled') || e.closest('[aria-disabled="true"],[inert]') ||
            !e.checkVisibility({checkOpacity:true,checkVisibilityCSS:true})) return null;
        if (action.kind==='fill' && (e.readOnly || e.getAttribute('aria-readonly')==='true')) return null;
        const r=e.getBoundingClientRect(), x=r.x+r.width/2, y=r.y+r.height/2;
        if (!r.width || !r.height || x<0 || y<0 || x>=innerWidth || y>=innerHeight) return null;
        const hit=document.elementFromPoint(x,y);
        if (!e.contains(hit)) return null;
        return {e,hit,x,y};
      };
      const click=(target,focusable,x,y)=>{
        const base={bubbles:true,cancelable:true,composed:true,clientX:x,clientY:y,view:window,button:0};
        const pointer={...base,pointerId:1,pointerType:'mouse',isPrimary:true};
        target.dispatchEvent(new PointerEvent('pointerover',pointer));
        target.dispatchEvent(new MouseEvent('mouseover',base));
        target.dispatchEvent(new PointerEvent('pointerdown',{...pointer,buttons:1}));
        const down=target.dispatchEvent(new MouseEvent('mousedown',{...base,buttons:1}));
        if (down && focusable && document.activeElement!==focusable) focusable.focus({preventScroll:true});
        target.dispatchEvent(new PointerEvent('pointerup',pointer));
        target.dispatchEvent(new MouseEvent('mouseup',base));
        target.dispatchEvent(new MouseEvent('click',{...base,detail:1}));
      };
      const insert=(e,text)=>{
        e.focus({preventScroll:true});
        if ('value' in e && (e.tagName==='INPUT' || e.tagName==='TEXTAREA')) {
          e.select();
          // execCommand keeps undo and fires real beforeinput/input events (React, Vue, etc.).
          if (document.execCommand('insertText',false,text) && e.value===text) {
            e.dispatchEvent(new Event('change',{bubbles:true})); return true;
          }
          const proto=e.tagName==='INPUT' ? HTMLInputElement.prototype : HTMLTextAreaElement.prototype;
          Object.getOwnPropertyDescriptor(proto,'value').set.call(e,text);
          e.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'insertText',data:text}));
          e.dispatchEvent(new Event('change',{bubbles:true}));
          return e.value===text;
        }
        const sel=getSelection(), range=document.createRange();
        range.selectNodeContents(e); sel.removeAllRanges(); sel.addRange(range);
        if (!document.execCommand('insertText',false,text) || e.innerText.trim()!==text.trim()) {
          e.textContent=text;
          e.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'insertText',data:text}));
        }
        return true;
      };
      const scroll=delta=>{
        const x=innerWidth/2, y=innerHeight*0.6, hit=document.elementFromPoint(x,y);
        hit?.dispatchEvent(new WheelEvent('wheel',{bubbles:true,cancelable:true,deltaY:delta,clientX:x,clientY:y}));
        let s=hit;
        while (s && s!==document.body && s!==document.documentElement) {
          const o=getComputedStyle(s).overflowY;
          if ((o==='auto' || o==='scroll') && s.scrollHeight>s.clientHeight+2) { s.scrollBy(0,delta); return; }
          s=s.parentElement;
        }
        window.scrollBy(0,delta);
      };

      // Returns 'ok', 'stale' (observe again) or 'unconfirmed' (dropdown; inspect before retrying).
      cache.act=(action,text)=>{
        if (action.kind==='wait') return 'ok';
        if (action.kind==='scroll') { scroll(action.delta); return 'ok'; }
        const t=resolve(action);
        if (!t) return action.kind==='select' ? 'unconfirmed' : 'stale';
        if (action.kind==='select') {
          const e=t.e;
          if (e.tagName!=='SELECT' || ![...e.options].some(o=>o.value===action.value &&
              !o.disabled && !o.closest('optgroup[disabled]'))) return 'unconfirmed';
          e.value=action.value;
          e.dispatchEvent(new Event('input',{bubbles:true}));
          e.dispatchEvent(new Event('change',{bubbles:true}));
          return 'ok';
        }
        const focusable=t.e.matches('input,textarea,select,button,a[href],[tabindex],[contenteditable="true"]') ? t.e : null;
        click(t.hit,focusable,t.x,t.y);
        if (action.kind==='fill') return insert(t.e,text) ? 'ok' : 'stale';
        return 'ok';
      };

      // After input: wait two frames, or for an autocomplete listbox after typing into a combobox.
      cache.settle=action=>new Promise(resolve=>{
        const field=cache.nodes.get(action.node);
        const autocomplete=action.kind==='fill' && field?.getAttribute('role')==='combobox';
        let frames=0, stopped=false;
        const finish=()=>{stopped=true;resolve(true)};
        setTimeout(finish,autocomplete ? 200 : 50);
        const ready=()=>{
          if (stopped) return;
          const ids=(field?.getAttribute('aria-controls')||field?.getAttribute('aria-owns')||'')
            .split(/\s+/).filter(Boolean);
          const roots=ids.length ? ids.map(id=>document.getElementById(id)).filter(Boolean) : [document];
          const options=roots.flatMap(root=>[...root.querySelectorAll('[role="option"]')]);
          if (++frames>=2 && (!autocomplete || options.some(e=>{
            const r=e.getBoundingClientRect();
            return r.width && r.height && r.bottom>0 && r.top<innerHeight &&
              e.checkVisibility({checkOpacity:true,checkVisibilityCSS:true});
          }))) finish();
          else requestAnimationFrame(ready);
        };
        requestAnimationFrame(ready);
      });
      return cache;
    })();
    """#

    /// Bodies passed to `callAsyncJavaScript`. Each returns a non-null value.
    static let snapshotBody = "const s = A.snapshot(); return s ? JSON.stringify(s) : '';"
    static let markerBody = "return A.marker() ?? '';"
    static let nodeKeyBody = "return A.nodeKey(node);"
    static let actBody = "return A.act(action, text);"
    static let settleBody = "return await A.settle(action);"
}
