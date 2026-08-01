#ifndef __RCCP_LIST_H
#define __RCCP_LIST_H

#define LIST_POISON1 ((void *) 0x00100100)
#define LIST_POISON2 ((void *) 0x00200200)

#define gslboffsetof(TYPE, MEMBER) ((size_t)&((TYPE *)0)->MEMBER)
#define container_of(ptr, type, member) ({\
		typeof(((type *)0)->member) *__mptr = (ptr);\
		(type *)((char *)__mptr - gslboffsetof(type,member));})

struct list_head {
	struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}


static inline void __list_add(struct list_head *new,
		struct list_head *prev,
		struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

//向head后面插入一个新的节点，每次添加都在head后的第一个节点
static inline void list_add(struct list_head *new, struct list_head *head)//
{
	__list_add(new, head, head->next);
}

//head为头节点的最后一个节点后插入新节点
static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
}

//删除next和prev之间的一个节点
static inline void __list_del(struct list_head * prev, struct list_head * next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = LIST_POISON1;
	entry->prev = LIST_POISON2;
}

//new指向的节点代替old指向的节点
static inline void list_replace(struct list_head *old,
		struct list_head *new)
{
	new->next = old->next;
	new->next->prev = new;
	new->prev = old->prev;
	new->prev->next = new;
}

//new指向的节点代替old指向的节点,并且初始化old指向的节点
static inline void list_replace_init(struct list_head *old,
		struct list_head *new)
{
	list_replace(old, new);
	INIT_LIST_HEAD(old);
}

//删除entry指向的节点并且初始化entry指向的节点
static inline void list_del_init(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	INIT_LIST_HEAD(entry);
}

//将list指向的节点从链表中删除后添加到head指向节点后的第一个节点
static inline void list_move(struct list_head *list, struct list_head *head)
{
	__list_del(list->prev, list->next);
	list_add(list, head);
}

//将list指向的节点从链表中删除后添加到head指向节点为首节点后的尾部最后一个节点后
static inline void list_move_tail(struct list_head *list,
		struct list_head *head)
{
	__list_del(list->prev, list->next);
	list_add_tail(list, head);
}

//将list指向节点和head指向节点连起来
static inline int list_is_last(const struct list_head *list,
		const struct list_head *head)
{
	return list->next == head;
}

//判断以head为链表首节点的链表是否为空
static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}

//判断以head为链表首节点的链表是否为空,很谨慎的判断
static inline int list_empty_careful(const struct list_head *head)
{
	struct list_head *next = head->next;
	return (next == head) && (next == head->prev);
}

//将list所指节点和head所指节点从原链表中分割出来,原链表依然连续
static inline void __list_splice(struct list_head *list,
		struct list_head *head)
{
	struct list_head *first = list->next;
	struct list_head *last = list->prev;
	struct list_head *at = head->next;

	first->prev = head;
	head->next = first;

	last->next = at;
	at->prev = last;
}

//如果list不为空节点,则将list和head之间链表分割出来
static inline void list_splice(struct list_head *list, struct list_head *head)
{
	if (!list_empty(list))
		__list_splice(list, head);
}

//如果list不为空节点,则将list和head之间链表分割出来,并且初始化list所指节点
static inline void list_splice_init(struct list_head *list,
		struct list_head *head)
{
	if (!list_empty(list)) {
		__list_splice(list, head);
		INIT_LIST_HEAD(list);
	}
}

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_for_each(pos, head) \
	for (pos = (head)->next;pos != (head); \
			pos = pos->next)

#define __list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

#define list_for_each_prev(pos, head) \
	for (pos = (head)->prev; pos != (head); \
			pos = pos->prev)

#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
			pos = n, n = pos->next)

#define list_for_each_entry(pos, head, member) \
	for (pos = list_entry((head)->next, typeof(*pos), member); \
			&pos->member != (head); \
			pos = list_entry(pos->member.next, typeof(*pos), member))

#define list_for_each_entry_reverse(pos, head, member) \
	for (pos = list_entry((head)->prev, typeof(*pos), member); \
			&pos->member != (head); \
			pos = list_entry(pos->member.prev, typeof(*pos), member))

#define list_prepare_entry(pos, head, member) \
	((pos) ? : list_entry(head, typeof(*pos), member))


#define list_for_each_entry_continue(pos, head, member) \
	for (pos = list_entry(pos->member.next, typeof(*pos), member); \
			prefetch(pos->member.next), &pos->member != (head); \
			pos = list_entry(pos->member.next, typeof(*pos), member))

#define list_for_each_entry_from(pos, head, member) \
	for (; prefetch(pos->member.next), &pos->member != (head); \
			pos = list_entry(pos->member.next, typeof(*pos), member))


#define list_for_each_entry_safe(pos, n, head, member) \
	for (pos = list_entry((head)->next, typeof(*pos), member), \
			n = list_entry(pos->member.next, typeof(*pos), member); \
			&pos->member != (head); \
			pos = n, n = list_entry(n->member.next, typeof(*n), member))


#define list_for_each_entry_safe_continue(pos, n, head, member) \
	for (pos = list_entry(pos->member.next, typeof(*pos), member), \
			n = list_entry(pos->member.next, typeof(*pos), member); \
			&pos->member != (head); \
			pos = n, n = list_entry(n->member.next, typeof(*n), member))

#define list_for_each_entry_safe_from(pos, n, head, member) \
	for (n = list_entry(pos->member.next, typeof(*pos), member); \
			&pos->member != (head); \
			pos = n, n = list_entry(n->member.next, typeof(*n), member))

#define list_for_each_entry_safe_reverse(pos, n, head, member) \
	for (pos = list_entry((head)->prev, typeof(*pos), member), \
			n = list_entry(pos->member.prev, typeof(*pos), member); \
			&pos->member != (head); \
			pos = n, n = list_entry(n->member.prev, typeof(*n), member))
#endif
