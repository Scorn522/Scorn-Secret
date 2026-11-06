package com.himitsu.secret.core;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;

/** Identity membership survives hostile UUID/id/hashCode changes without retaining dead entities. */
final class WeakTargetSet<T> {
    private static final class Node<T> {
        final WeakReference<T> key;
        final WeakReference<Object> scope;
        final Node<T> next;
        Node(T key,Object scope,Node<T> next) { this.key=new WeakReference<>(key); this.scope=new WeakReference<>(scope); this.next=next; }
        Node(Node<T> source,Node<T> next) { key=source.key; scope=source.scope; this.next=next; }
    }
    private static final class Bucket<T> { volatile Node<T> head; }
    private final Bucket<T>[] buckets;
    private int writes;
    @SuppressWarnings("unchecked") WeakTargetSet() {
        buckets=(Bucket<T>[])new Bucket<?>[256]; for(int i=0;i<buckets.length;i++) buckets[i]=new Bucket<>();
    }
    boolean contains(T key) {
        if(key==null) return false;
        for(Node<T> n=buckets[System.identityHashCode(key)&255].head;n!=null;n=n.next) if(n.key.get()==key) return true;
        return false;
    }
    synchronized void add(T key,Object scope) {
        if(contains(key)) return;
        Bucket<T> b=buckets[System.identityHashCode(key)&255]; b.head=new Node<>(key,scope,b.head);
        if((++writes&63)==0) compact(null,false);
    }
    synchronized void clearScope(Object scope) { compact(scope,true); }
    synchronized void clear() { for(Bucket<T> b:buckets) b.head=null; }
    private void compact(Object scope,boolean removeScope) {
        for(Bucket<T> b:buckets) {
            List<Node<T>> live=new ArrayList<>();
            for(Node<T> n=b.head;n!=null;n=n.next)
                if(n.key.get()!=null && !(removeScope && n.scope.get()==scope)) live.add(n);
            Node<T> head=null;
            for(int i=live.size()-1;i>=0;i--) head=new Node<>(live.get(i),head);
            b.head=head;
        }
    }
}
