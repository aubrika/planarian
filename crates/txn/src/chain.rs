//! The journal's hash chain as a decision (I18), apart from the I/O in
//! `journal.rs`. Hashing stays outside: SHA-256 is trusted (P5), so each
//! record enters as a `Link` carrying the head it claims to follow (`prev`)
//! and the head after it (`next`, from `journal::chain`). What is proved here
//! is everything else: a record follows exactly when its seq is the next one
//! and its `prev` is the current head; a segment is accepted exactly when
//! every record follows, and otherwise the first that does not is reported;
//! and what the writer appends always follows.

use planarian_schema::Hash;
use vstd::prelude::*;

verus! {

/// One record as the chain sees it.
#[derive(Clone, Copy)]
pub struct Link {
    pub seq: u64,
    /// The chain head this record says it follows.
    pub prev: Hash,
    /// The chain head after it: SHA-256(`prev` ‖ `seq` ‖ payload).
    pub next: Hash,
}

/// Whether a record follows the chain, and if not, why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Follows {
    Yes,
    /// Its seq is not the next one: a torn tail, or a leftover.
    OutOfSequence,
    /// The next seq, but not chained to the head: edited or damaged (I18).
    Unchained,
}

/// Two hashes are the same bytes.
pub open spec fn same(a: Hash, b: Hash) -> bool {
    a.0@ == b.0@
}

pub open spec fn follows_spec(last: u64, head: Hash, seq: u64, prev: Hash) -> Follows {
    if last == u64::MAX || seq != last + 1 {
        Follows::OutOfSequence
    } else if !same(prev, head) {
        Follows::Unchained
    } else {
        Follows::Yes
    }
}

/// The (last seq, head) a segment's `i`-th record must follow.
pub open spec fn cursor_at(last: u64, head: Hash, links: Seq<Link>, i: int) -> (u64, Hash) {
    if i == 0 {
        (last, head)
    } else {
        (links[i - 1].seq, links[i - 1].next)
    }
}

pub open spec fn link_ok(last: u64, head: Hash, links: Seq<Link>, i: int) -> bool {
    follows_spec(cursor_at(last, head, links, i).0, cursor_at(last, head, links, i).1, links[i].seq, links[i].prev)
        == Follows::Yes
}

/// The first `n` records of the segment follow the chain.
pub open spec fn chained_upto(last: u64, head: Hash, links: Seq<Link>, n: int) -> bool {
    forall|i: int| 0 <= i < n ==> #[trigger] link_ok(last, head, links, i)
}

/// I18 for a segment starting after (`last`, `head`): every record follows.
pub open spec fn chained(last: u64, head: Hash, links: Seq<Link>) -> bool {
    chained_upto(last, head, links, links.len() as int)
}

pub fn hash_eq(a: &Hash, b: &Hash) -> (r: bool)
    ensures
        r == same(*a, *b),
{
    let mut i: usize = 0;
    while i < 32
        invariant
            0 <= i <= 32,
            a.0@.len() == 32,
            b.0@.len() == 32,
            forall|j: int| 0 <= j < i ==> a.0@[j] == b.0@[j],
        decreases 32 - i,
    {
        if a.0[i] != b.0[i] {
            return false;
        }
        i += 1;
    }
    assert(a.0@ =~= b.0@);
    true
}

/// The check every read path applies to each record (`journal::scan`).
pub fn follows(last: u64, head: &Hash, seq: u64, prev: &Hash) -> (r: Follows)
    ensures
        r == follows_spec(last, *head, seq, *prev),
{
    if last == u64::MAX || seq != last + 1 {
        Follows::OutOfSequence
    } else if !hash_eq(prev, head) {
        Follows::Unchained
    } else {
        Follows::Yes
    }
}

/// How a whole segment checked out.
pub enum Verdict {
    /// Every record follows; the segment ends at this seq and head.
    Chained { last: u64, head: Hash },
    /// The record at `at` is the first that does not follow.
    Break { at: usize, why: Follows },
}

/// Check a segment (`journal::verify_chain`): accepts exactly a chained
/// segment, and otherwise reports its first break.
pub fn verify(last: u64, head: Hash, links: &Vec<Link>) -> (r: Verdict)
    ensures
        (r is Chained) == chained(last, head, links@),
        r matches Verdict::Chained { last: l, head: h } ==> (l, h) == cursor_at(last, head, links@, links@.len() as int),
        r matches Verdict::Break { at, why } ==> {
            &&& at < links@.len()
            &&& chained_upto(last, head, links@, at as int)
            &&& !link_ok(last, head, links@, at as int)
            &&& why != Follows::Yes
        },
{
    let mut i: usize = 0;
    let mut cur_last = last;
    let mut cur_head = head;
    while i < links.len()
        invariant
            0 <= i <= links@.len(),
            chained_upto(last, head, links@, i as int),
            (cur_last, cur_head) == cursor_at(last, head, links@, i as int),
        decreases links@.len() - i,
    {
        let l = links[i];
        assert(l == links@[i as int]);
        let f = follows(cur_last, &cur_head, l.seq, &l.prev);
        match f {
            Follows::Yes => {},
            _ => {
                assert(!link_ok(last, head, links@, i as int));
                return Verdict::Break { at: i, why: f };
            },
        }
        assert(link_ok(last, head, links@, i as int));
        cur_last = l.seq;
        cur_head = l.next;
        i += 1;
        assert(chained_upto(last, head, links@, i as int)) by {
            assert forall|j: int| 0 <= j < i implies #[trigger] link_ok(last, head, links@, j) by {
                if j < i - 1 {
                    assert(chained_upto(last, head, links@, (i - 1) as int));
                }
            }
        }
    }
    Verdict::Chained { last: cur_last, head: cur_head }
}

/// The seq and `prev` the writer gives the next record (`journal::append`):
/// the next seq, and the current head.
pub fn next_link(last: u64, head: &Hash) -> (r: (u64, Hash))
    requires
        last < u64::MAX,
    ensures
        follows_spec(last, *head, r.0, r.1) == Follows::Yes,
        r.0 == last + 1,
        same(r.1, *head),
{
    (last + 1, *head)
}

/// I18's writing half: a chained segment with a record appended the way
/// `next_link` makes it is still chained. By induction, every journal the
/// writer produces is chained, so a break on read is damage or an edit.
pub proof fn appending_keeps_the_chain(last: u64, head: Hash, links: Seq<Link>, l: Link)
    requires
        chained(last, head, links),
        follows_spec(
            cursor_at(last, head, links, links.len() as int).0,
            cursor_at(last, head, links, links.len() as int).1,
            l.seq,
            l.prev,
        ) == Follows::Yes,
    ensures
        chained(last, head, links.push(l)),
{
    let s = links.push(l);
    assert forall|i: int| 0 <= i < s.len() implies #[trigger] link_ok(last, head, s, i) by {
        if i < links.len() {
            assert(link_ok(last, head, links, i));
            if i > 0 {
                assert(s[i - 1] == links[i - 1]);
            }
            assert(s[i] == links[i]);
        } else {
            assert(s[i] == l);
            if i > 0 {
                assert(s[i - 1] == links[i - 1]);
            }
        }
    }
}

/// An edit is caught: if a record's `next` changes (its payload was edited,
/// so its hash changed, P5) while the record after it is untouched, the
/// segment no longer verifies.
pub proof fn an_edited_record_breaks_the_chain(last: u64, head: Hash, links: Seq<Link>, i: int, edited: Hash)
    requires
        chained(last, head, links),
        0 <= i < links.len() - 1,
        !same(edited, links[i].next),
    ensures
        !chained(last, head, links.update(i, Link { next: edited, ..links[i] })),
{
    let s = links.update(i, Link { next: edited, ..links[i] });
    assert(link_ok(last, head, links, i + 1));
    assert(s[i + 1] == links[i + 1]);
    assert(!link_ok(last, head, s, i + 1));
}

} // verus!
